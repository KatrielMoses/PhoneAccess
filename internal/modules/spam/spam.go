package spam

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

const (
	moduleName = "spam"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Source interface {
	Name() string
	URL(number *core.PhoneNumber) string
	Parse(body []byte) SourceResult
}

type Module struct {
	httpClient HTTPClient
	limiter    *core.RateLimiter
	sources    []Source
}

type Option func(*Module)

type SourceResult struct {
	Source     string
	Reports    int
	CallerType string
	Snippets   []string
	MostRecent *time.Time
	Available  bool
	Error      string
}

type SpamResult struct {
	TotalReports     int
	SourcesChecked   []string
	SourcesWithHits  []string
	CallerType       string
	SpamScore        int
	ReportSnippets   []string
	MostRecentReport string
	Safe             bool
	SourceStatuses   map[string]string
}

func New(opts ...Option) *Module {
	m := &Module{
		httpClient: core.NewHTTPClient(core.DefaultHTTPTimeout),
		limiter:    core.NewRateLimiter(2 * time.Second),
		sources: []Source{
			eightHundredNotesSource{},
			whoCalledUsSource{},
			spamCallsSource{},
		},
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func WithHTTPClient(client HTTPClient) Option {
	return func(m *Module) {
		if client != nil {
			m.httpClient = client
		}
	}
}

func WithRateLimiter(limiter *core.RateLimiter) Option {
	return func(m *Module) {
		m.limiter = limiter
	}
}

func WithSources(sources ...Source) Option {
	return func(m *Module) {
		if len(sources) > 0 {
			m.sources = sources
		}
	}
}

func (m *Module) Name() string {
	return moduleName
}

func (m *Module) Description() string {
	return "Public spam-report reputation checks across caller complaint databases."
}

func (m *Module) RequiresAPIKey() bool {
	return false
}

func (m *Module) Tier() core.ModuleTier {
	return core.TierPassive
}

func (m *Module) DryRun(ctx context.Context, number *core.PhoneNumber) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (m *Module) RunPassive(ctx context.Context, number *core.PhoneNumber) (*core.ModuleResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	return &core.ModuleResult{
		ModuleName: m.Name(),
		Status:     core.ModuleStatusSkipped,
		Findings: map[string]string{
			"skipped": "true",
			"note":    "passive mode disables active spam reputation lookups",
		},
		Evidence: []string{"Passive mode enabled; spam module made no network requests."},
	}, nil
}

func (m *Module) Run(ctx context.Context, number *core.PhoneNumber) (*core.ModuleResult, error) {
	results := make([]SourceResult, 0, len(m.sources))
	for _, source := range m.sources {
		results = append(results, m.querySource(ctx, source, number))
	}

	aggregated := aggregate(results)
	findings := findingsFromSpamResult(aggregated)
	return &core.ModuleResult{
		ModuleName: m.Name(),
		Status:     core.ModuleStatusSuccess,
		Findings:   findings,
		Evidence:   evidenceFromStatuses(aggregated.SourceStatuses),
	}, nil
}

func (m *Module) querySource(ctx context.Context, source Source, number *core.PhoneNumber) SourceResult {
	result := SourceResult{
		Source:    source.Name(),
		Available: false,
	}

	endpoint := source.URL(number)
	parsed, err := url.Parse(endpoint)
	if err != nil {
		result.Error = "invalid source URL"
		return result
	}

	if m.limiter != nil {
		if err := m.limiter.Wait(ctx, parsed.Hostname()); err != nil {
			result.Error = err.Error()
			return result
		}
	}

	requestCtx, cancel := context.WithTimeout(ctx, core.DefaultHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	core.SetDefaultHeaders(req)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		result.Available = true
		return result
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		result.Error = fmt.Sprintf("http status %d", resp.StatusCode)
		return result
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		result.Error = err.Error()
		return result
	}

	parsedResult := source.Parse(body)
	parsedResult.Source = source.Name()
	parsedResult.Available = true
	if parsedResult.CallerType == "" {
		parsedResult.CallerType = "unknown"
	}
	return parsedResult
}

func aggregate(results []SourceResult) SpamResult {
	out := SpamResult{
		CallerType:     "unknown",
		SourceStatuses: map[string]string{},
	}
	typeVotes := map[string]int{}
	var mostRecent *time.Time

	for _, result := range results {
		out.SourcesChecked = append(out.SourcesChecked, result.Source)
		if !result.Available {
			status := "unavailable"
			if strings.TrimSpace(result.Error) != "" {
				status += ": " + result.Error
			}
			out.SourceStatuses[result.Source] = status
			continue
		}

		hit := result.Reports > 0 || len(result.Snippets) > 0 || normalizeCallerType(result.CallerType) != "unknown"
		if !hit {
			out.SourceStatuses[result.Source] = "no results"
			continue
		}

		out.TotalReports += result.Reports
		out.SourcesWithHits = append(out.SourcesWithHits, result.Source)
		callerType := normalizeCallerType(result.CallerType)
		if callerType != "unknown" {
			typeVotes[callerType]++
		}
		out.ReportSnippets = append(out.ReportSnippets, result.Snippets...)
		if result.MostRecent != nil && (mostRecent == nil || result.MostRecent.After(*mostRecent)) {
			copyTime := *result.MostRecent
			mostRecent = &copyTime
		}
		out.SourceStatuses[result.Source] = "hit"
	}

	out.CallerType = selectCallerType(typeVotes)
	out.ReportSnippets = selectSnippets(out.ReportSnippets, 5)
	if mostRecent != nil {
		out.MostRecentReport = mostRecent.Format("2006-01-02")
	}
	out.Safe = out.TotalReports == 0
	out.SpamScore = spamScore(out.TotalReports, out.CallerType, len(out.SourcesWithHits))
	return out
}

func spamScore(totalReports int, callerType string, sourcesWithHits int) int {
	score := totalReports * 5
	if score > 50 {
		score = 50
	}
	switch normalizeCallerType(callerType) {
	case "scammer", "fraudster":
		score += 20
	case "debt collector", "robocall":
		score += 10
	case "telemarketer":
		score += 5
	}
	if sourcesWithHits >= 2 {
		score += 15
	}
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func selectCallerType(votes map[string]int) string {
	if len(votes) == 0 {
		return "unknown"
	}
	types := make([]string, 0, len(votes))
	for callerType := range votes {
		types = append(types, callerType)
	}
	sort.Slice(types, func(i, j int) bool {
		if votes[types[i]] == votes[types[j]] {
			return callerSeverity(types[i]) > callerSeverity(types[j])
		}
		return votes[types[i]] > votes[types[j]]
	})
	return types[0]
}

func callerSeverity(callerType string) int {
	switch normalizeCallerType(callerType) {
	case "scammer", "fraudster":
		return 3
	case "debt collector", "robocall":
		return 2
	case "telemarketer":
		return 1
	default:
		return 0
	}
}

func findingsFromSpamResult(result SpamResult) map[string]string {
	return map[string]string{
		"total_reports":      strconv.Itoa(result.TotalReports),
		"sources_checked":    strings.Join(result.SourcesChecked, ", "),
		"sources_with_hits":  strings.Join(result.SourcesWithHits, ", "),
		"caller_type":        result.CallerType,
		"spam_score":         strconv.Itoa(result.SpamScore),
		"risk":               riskLabel(result.SpamScore),
		"report_snippets":    strings.Join(result.ReportSnippets, "\n"),
		"most_recent_report": result.MostRecentReport,
		"safe":               strconv.FormatBool(result.Safe),
		"source_statuses":    joinStatuses(result.SourceStatuses),
	}
}

func evidenceFromStatuses(statuses map[string]string) []string {
	if len(statuses) == 0 {
		return nil
	}
	names := make([]string, 0, len(statuses))
	for name := range statuses {
		names = append(names, name)
	}
	sort.Strings(names)
	evidence := make([]string, 0, len(names))
	for _, name := range names {
		evidence = append(evidence, name+": "+statuses[name])
	}
	return evidence
}

func joinStatuses(statuses map[string]string) string {
	names := make([]string, 0, len(statuses))
	for name := range statuses {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+"="+statuses[name])
	}
	return strings.Join(parts, "; ")
}

func riskLabel(score int) string {
	switch {
	case score == 0:
		return "CLEAN"
	case score < 25:
		return "LOW"
	case score < 50:
		return "MODERATE"
	case score < 75:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}

func (m *Module) ProxyAware() bool { return true }
