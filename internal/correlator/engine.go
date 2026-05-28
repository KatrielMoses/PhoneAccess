package correlator

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

const DefaultTimeout = 12 * time.Second

type ClaimSource interface {
	Name() string
	Jurisdiction() []string
	Fetch(ctx context.Context, e164 string) ([]PIIClaim, error)
}

type DryRunSource interface {
	DryRun(ctx context.Context, e164 string) error
}

type CandidateNameSource interface {
	WithCandidateNames(names []string) ClaimSource
}

type Engine struct {
	sources []ClaimSource
	timeout time.Duration
	passive bool
	now     func() time.Time
}

type EngineOption func(*Engine)

func NewEngine(sources []ClaimSource, opts ...EngineOption) *Engine {
	engine := &Engine{
		sources: sources,
		timeout: DefaultTimeout,
		now:     func() time.Time { return time.Now().UTC() },
	}
	for _, opt := range opts {
		opt(engine)
	}
	return engine
}

func WithTimeout(timeout time.Duration) EngineOption {
	return func(engine *Engine) {
		if timeout > 0 {
			engine.timeout = timeout
		}
	}
}

func WithPassive(passive bool) EngineOption {
	return func(engine *Engine) {
		engine.passive = passive
	}
}

func WithNow(now func() time.Time) EngineOption {
	return func(engine *Engine) {
		if now != nil {
			engine.now = now
		}
	}
}

func (e *Engine) Run(ctx context.Context, e164 string) (*UnifiedIdentityRecord, error) {
	now := e.now().UTC()
	jurisdiction := JurisdictionForE164(e164)
	record := &UnifiedIdentityRecord{
		Status:       StatusSuccess,
		Jurisdiction: jurisdiction,
		GeneratedAt:  now,
		Names:        []FieldCandidate{},
		Addresses:    []FieldCandidate{},
		DOBs:         []FieldCandidate{},
		Emails:       []FieldCandidate{},
		SocialLinks:  []FieldCandidate{},
		Conflicts:    []Conflict{},
		Claims:       []PIIClaim{},
		SourceRuns:   []SourceRun{},
	}
	if e.passive {
		record.Status = StatusSkipped
		record.Note = "passive mode disables identity correlation sources"
		return record, nil
	}

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	initialSources, _ := splitDeferredSources(SelectSources(e.sources, e164, false))
	_, deferredSources := splitDeferredSources(SelectSources(e.sources, e164, true))
	claims, runs := e.fetchAll(ctx, e164, initialSources)
	record.SourceRuns = append(record.SourceRuns, runs...)
	if len(deferredSources) > 0 && strings.EqualFold(jurisdiction, "GB") {
		names := candidateNamesFromClaims(claims)
		if len(names) > 0 {
			deferredClaims, deferredRuns := e.fetchAll(ctx, e164, withCandidateNames(deferredSources, names))
			claims = append(claims, deferredClaims...)
			record.SourceRuns = append(record.SourceRuns, deferredRuns...)
		}
	}

	record.Claims = normalizeClaims(claims, now)
	e.merge(record, now)
	return record, nil
}

func (e *Engine) fetchAll(ctx context.Context, e164 string, selected []ClaimSource) ([]PIIClaim, []SourceRun) {
	var mu sync.Mutex
	claims := []PIIClaim{}
	runs := []SourceRun{}
	group, groupCtx := errgroup.WithContext(ctx)
	for _, source := range selected {
		source := source
		group.Go(func() error {
			if dryRunner, ok := source.(DryRunSource); ok {
				if err := dryRunner.DryRun(groupCtx, e164); err != nil {
					run := SourceRun{Name: source.Name(), Status: "skipped", Error: err.Error()}
					mu.Lock()
					runs = append(runs, run)
					mu.Unlock()
					return nil
				}
			}
			fetched, err := source.Fetch(groupCtx, e164)
			run := SourceRun{Name: source.Name(), ClaimsCount: len(fetched)}
			if err != nil {
				run.Status = "error"
				if skippedSourceError(err) {
					run.Status = "skipped"
				}
				run.Error = err.Error()
				mu.Lock()
				runs = append(runs, run)
				mu.Unlock()
				return nil
			}
			run.Status = "success"
			if len(fetched) == 0 {
				run.Status = "no_claims"
			}
			mu.Lock()
			claims = append(claims, fetched...)
			runs = append(runs, run)
			mu.Unlock()
			return nil
		})
	}
	_ = group.Wait()
	sort.SliceStable(runs, func(i, j int) bool {
		return strings.ToLower(runs[i].Name) < strings.ToLower(runs[j].Name)
	})
	return claims, runs
}

func skippedSourceError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "missing") || strings.Contains(message, "skipped")
}

func (e *Engine) merge(record *UnifiedIdentityRecord, now time.Time) {
	candidates := candidatesFromClusters(clusterClaims(record.Claims), now)
	candidates, conflicts := applyConflicts(candidates)
	for i := range candidates {
		candidates[i].ConfidenceLabel = ConfidenceLabel(candidates[i].Confidence)
		candidates[i].Suppressed = candidates[i].Confidence < LowConfidenceThreshold
	}
	record.Conflicts = conflicts

	for _, candidate := range candidates {
		if candidate.Suppressed {
			record.SuppressedCount++
		}
		switch candidate.Field {
		case FieldName:
			record.Names = append(record.Names, candidate)
		case FieldAddress:
			record.Addresses = append(record.Addresses, candidate)
		case FieldDOB:
			record.DOBs = append(record.DOBs, candidate)
		case FieldEmail:
			record.Emails = append(record.Emails, candidate)
		case FieldSocialLink:
			record.SocialLinks = append(record.SocialLinks, candidate)
		}
	}
	for _, list := range []*[]FieldCandidate{&record.Names, &record.Addresses, &record.DOBs, &record.Emails, &record.SocialLinks} {
		sortCandidates(*list)
	}
	record.OverallConfidence = roundConfidence(overallConfidence(record))
	if record.SuppressedCount > 0 {
		record.SuppressionNote = "fields below 0.45 confidence are suppressed from terminal display but retained in JSON"
	}
}

func SelectSources(all []ClaimSource, e164 string, includeDeferred bool) []ClaimSource {
	allowed := SelectSourceNames(e164, includeDeferred)
	out := make([]ClaimSource, 0, len(all))
	for _, source := range all {
		if source == nil {
			continue
		}
		if allowed[strings.ToLower(source.Name())] {
			out = append(out, source)
		}
	}
	return out
}

func SelectSourceNames(e164 string, includeDeferred bool) map[string]bool {
	names := map[string]bool{}
	switch {
	case strings.HasPrefix(e164, "+91"):
		for _, name := range []string{"OpenCNAM", "NumLookup", "LeakSight", "IPQualityScore", "Veriphone", "AbstractAPI", "Twilio", "Neutrino HLR"} {
			names[strings.ToLower(name)] = true
		}
	case strings.HasPrefix(e164, "+1"):
		for _, name := range []string{"OpenCNAM", "NumLookup", "Trestle", "LeakSight", "IPQualityScore", "Veriphone", "AbstractAPI", "Twilio", "Neutrino HLR"} {
			names[strings.ToLower(name)] = true
		}
	case strings.HasPrefix(e164, "+44"):
		for _, name := range []string{"OpenCNAM", "NumLookup", "LeakSight", "Veriphone", "AbstractAPI", "Twilio", "Neutrino HLR"} {
			names[strings.ToLower(name)] = true
		}
		if includeDeferred {
			names[strings.ToLower("Companies House")] = true
		}
	case strings.HasPrefix(e164, "+234"):
		for _, name := range []string{"OpenCNAM", "Veriphone", "AbstractAPI", "Twilio", "Neutrino HLR", "NigeriaPhoneBook"} {
			names[strings.ToLower(name)] = true
		}
	case strings.HasPrefix(e164, "+39"):
		for _, name := range []string{"OpenCNAM", "Veriphone", "AbstractAPI", "Twilio", "Neutrino HLR", "Pagine Bianche"} {
			names[strings.ToLower(name)] = true
		}
	case strings.HasPrefix(e164, "+55"):
		for _, name := range []string{"OpenCNAM", "Veriphone", "AbstractAPI", "Twilio", "Neutrino HLR", "TeleListas"} {
			names[strings.ToLower(name)] = true
		}
	case strings.HasPrefix(e164, "+54"):
		for _, name := range []string{"OpenCNAM", "Veriphone", "AbstractAPI", "Twilio", "Neutrino HLR", "Paginas Blancas Argentina"} {
			names[strings.ToLower(name)] = true
		}
	case strings.HasPrefix(e164, "+49"):
		for _, name := range []string{"OpenCNAM", "Veriphone", "AbstractAPI", "Twilio", "Neutrino HLR", "Das Telefonbuch"} {
			names[strings.ToLower(name)] = true
		}
	case hasAnyPrefix(e164, []string{"+20", "+966", "+971", "+965", "+974", "+973", "+968", "+962", "+961", "+964", "+212", "+213", "+216", "+218", "+249"}):
		for _, name := range []string{"OpenCNAM", "Veriphone", "AbstractAPI", "Twilio", "Neutrino HLR", "CallerKit"} {
			names[strings.ToLower(name)] = true
		}
	default:
		for _, name := range []string{"OpenCNAM", "NumLookup", "LeakSight", "IPQualityScore", "Veriphone", "AbstractAPI", "Twilio", "Neutrino HLR"} {
			names[strings.ToLower(name)] = true
		}
	}
	return names
}

func JurisdictionForE164(e164 string) string {
	switch {
	case strings.HasPrefix(e164, "+91"):
		return "IN"
	case strings.HasPrefix(e164, "+1"):
		return "US"
	case strings.HasPrefix(e164, "+44"):
		return "GB"
	case strings.HasPrefix(e164, "+234"):
		return "NG"
	case strings.HasPrefix(e164, "+39"):
		return "IT"
	case strings.HasPrefix(e164, "+55"):
		return "BR"
	case strings.HasPrefix(e164, "+54"):
		return "AR"
	case strings.HasPrefix(e164, "+49"):
		return "DE"
	default:
		return "ZZ"
	}
}

func hasAnyPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func splitDeferredSources(sources []ClaimSource) ([]ClaimSource, []ClaimSource) {
	initial := []ClaimSource{}
	deferred := []ClaimSource{}
	for _, source := range sources {
		if strings.EqualFold(source.Name(), "Companies House") {
			deferred = append(deferred, source)
			continue
		}
		initial = append(initial, source)
	}
	return initial, deferred
}

func withCandidateNames(sources []ClaimSource, names []string) []ClaimSource {
	out := make([]ClaimSource, 0, len(sources))
	for _, source := range sources {
		if named, ok := source.(CandidateNameSource); ok {
			out = append(out, named.WithCandidateNames(names))
			continue
		}
		out = append(out, source)
	}
	return out
}

func candidateNamesFromClaims(claims []PIIClaim) []string {
	seen := map[string]string{}
	for _, claim := range claims {
		if claim.Field != FieldName {
			continue
		}
		norm := NormalizeName(claim.Value)
		if norm != "" {
			seen[norm] = strings.TrimSpace(claim.Value)
		}
	}
	out := make([]string, 0, len(seen))
	for _, value := range seen {
		out = append(out, value)
	}
	return out
}

func normalizeClaims(claims []PIIClaim, now time.Time) []PIIClaim {
	out := make([]PIIClaim, 0, len(claims))
	for _, claim := range claims {
		claim.Value = strings.TrimSpace(claim.Value)
		if claim.Value == "" {
			continue
		}
		if claim.FetchedAt.IsZero() {
			claim.FetchedAt = now
		}
		if claim.Weight <= 0 {
			claim.Weight = claim.Source.TierWeight
		}
		out = append(out, claim)
	}
	return out
}

func overallConfidence(record *UnifiedIdentityRecord) float64 {
	max := 0.0
	for _, list := range [][]FieldCandidate{record.Names, record.Addresses, record.DOBs, record.Emails, record.SocialLinks} {
		if len(list) > 0 && list[0].Confidence > max {
			max = list[0].Confidence
		}
	}
	return max
}
