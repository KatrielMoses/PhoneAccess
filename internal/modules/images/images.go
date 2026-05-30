package images

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/config"
	"github.com/KatrielMoses/PhoneAccess/internal/core"
	"github.com/KatrielMoses/PhoneAccess/internal/storage"
)

const (
	moduleName       = "image_intelligence"
	keyName          = "TINEYE_API_KEY"
	thresholdEnvKey  = "PHASH_HAMMING_THRESHOLD"
	defaultThreshold = 10
	tineyeDelay      = 2 * time.Second
)

// PhashStore abstracts the SQLite photo-hash store for testability.
type PhashStore interface {
	FindSimilarHashes(phash string, threshold, selfInvestigationID int) ([]storage.PhotoHashRecord, error)
	Close() error
}

// Module implements image intelligence: TinEye reverse search, manual search
// URL generation, and cross-session pHash deduplication.
// It is TierActive and runs only after messenger modules have completed
// (via the PostMessengerModule interface).
type Module struct {
	keyLoader   func() string
	threshold   int
	storeOpener func() (PhashStore, error)
	tineye      TinEyeSearcher
	rateLimiter *core.RateLimiter
}

// TinEyeSearcher is the interface for the TinEye reverse image search.
type TinEyeSearcher interface {
	Search(ctx context.Context, photoPath string) (core.TinEyeResult, error)
}

type Option func(*Module)

func New(opts ...Option) *Module {
	m := &Module{
		keyLoader:   loadKey,
		threshold:   resolveThreshold(),
		storeOpener: defaultStoreOpener,
		rateLimiter: core.NewRateLimiter(tineyeDelay),
	}
	for _, opt := range opts {
		opt(m)
	}
	// Build the default TinEye client only if no explicit searcher was injected.
	if m.tineye == nil {
		m.tineye = newTinEyeClient(m.keyLoader, m.rateLimiter)
	}
	return m
}

func WithKeyLoader(fn func() string) Option {
	return func(m *Module) { m.keyLoader = fn }
}

func WithTinEyeSearcher(s TinEyeSearcher) Option {
	return func(m *Module) { m.tineye = s }
}

func WithStoreOpener(fn func() (PhashStore, error)) Option {
	return func(m *Module) { m.storeOpener = fn }
}

func WithThreshold(t int) Option {
	return func(m *Module) {
		if t >= 0 {
			m.threshold = t
		}
	}
}

func WithRateLimiter(l *core.RateLimiter) Option {
	return func(m *Module) { m.rateLimiter = l }
}

// Module interface

func (m *Module) Name() string        { return moduleName }
func (m *Module) RequiresAPIKey() bool { return false }
func (m *Module) Tier() core.ModuleTier { return core.TierActive }
func (m *Module) ProxyAware() bool    { return true }
func (m *Module) Description() string {
	return "Reverse image search via TinEye API and cross-session pHash deduplication of messenger profile photos."
}

func (m *Module) DryRun(ctx context.Context, _ *core.PhoneNumber) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// Run returns a deferred placeholder; the real work happens in RunPostMessenger.
func (m *Module) Run(_ context.Context, _ *core.PhoneNumber) (*core.ModuleResult, error) {
	return &core.ModuleResult{
		ModuleName: moduleName,
		Status:     core.ModuleStatusSkipped,
		Findings: map[string]string{
			"skipped": "true",
			"reason":  "deferred to post-messenger pass",
		},
	}, nil
}

// RunPostMessenger implements core.PostMessengerModule.
func (m *Module) RunPostMessenger(ctx context.Context, number *core.PhoneNumber, report *core.InvestigationReport) (*core.ModuleResult, error) {
	photoPath, photoSource := resolvePhoto(report)
	if photoPath == "" {
		return &core.ModuleResult{
			ModuleName: moduleName,
			Status:     core.ModuleStatusSkipped,
			Findings: map[string]string{
				"skipped": "true",
				"reason":  "no profile photo available from messenger modules",
			},
			Evidence: []string{"No profile photo retrieved — WhatsApp or Telegram session required."},
		}, nil
	}

	phash := resolvePhash(report, photoSource)

	result := &core.ImageIntelResult{
		PhotoPath:   photoPath,
		PhotoSource: photoSource,
		PhotoPHash:  phash,
	}

	// TinEye reverse image search (opt-in via key).
	if key := m.keyLoader(); strings.TrimSpace(key) != "" {
		tineyeResult, err := m.tineye.Search(ctx, photoPath)
		if err == nil {
			result.TinEye = tineyeResult
		}
	}

	// URL generation always runs when a photo is available.
	result.ReverseURLs = buildReverseURLs(photoPath)

	// Cross-session pHash matching.
	if phash != "" {
		result.CrossSessionHits = m.findCrossSessionMatches(phash)
	}

	findings := buildFindings(result)

	return &core.ModuleResult{
		ModuleName: moduleName,
		Status:     core.ModuleStatusSuccess,
		Findings:   findings,
		Data:       result,
		Evidence:   []string{"Profile photo analysed via TinEye reverse image search and pHash cross-session deduplication."},
	}, nil
}

// resolvePhoto picks the first available profile photo from the messenger report.
func resolvePhoto(report *core.InvestigationReport) (path, source string) {
	if report.Messenger == nil {
		return "", ""
	}
	if report.Messenger.Telegram != nil && strings.TrimSpace(report.Messenger.Telegram.ProfilePhotoPath) != "" {
		return strings.TrimSpace(report.Messenger.Telegram.ProfilePhotoPath), "telegram"
	}
	if report.Messenger.WhatsApp != nil && strings.TrimSpace(report.Messenger.WhatsApp.ProfilePhotoPath) != "" {
		return strings.TrimSpace(report.Messenger.WhatsApp.ProfilePhotoPath), "whatsapp"
	}
	return "", ""
}

// resolvePhash returns the pHash for the given source from the messenger report.
func resolvePhash(report *core.InvestigationReport, source string) string {
	if report.Messenger == nil {
		return ""
	}
	switch source {
	case "telegram":
		if report.Messenger.Telegram != nil {
			return report.Messenger.Telegram.ProfilePhotoPHash
		}
	case "whatsapp":
		if report.Messenger.WhatsApp != nil {
			return report.Messenger.WhatsApp.ProfilePhotoPHash
		}
	}
	return ""
}

func (m *Module) findCrossSessionMatches(phash string) []core.CrossSessionMatch {
	store, err := m.storeOpener()
	if err != nil {
		return nil
	}
	defer store.Close()

	records, err := store.FindSimilarHashes(phash, m.threshold, 0)
	if err != nil || len(records) == 0 {
		return nil
	}

	hits := make([]core.CrossSessionMatch, 0, len(records))
	for _, r := range records {
		hits = append(hits, core.CrossSessionMatch{
			CaseID:      r.InvestigationID,
			PhoneE164:   r.PhoneE164,
			CaseName:    r.CaseName,
			HammingDist: r.HammingDist,
			FoundAt:     r.CreatedAt,
		})
	}
	return hits
}

func buildFindings(r *core.ImageIntelResult) map[string]string {
	f := map[string]string{
		"photo_path":        r.PhotoPath,
		"photo_source":      r.PhotoSource,
		"photo_phash":       r.PhotoPHash,
		"tineye_match_count": strconv.Itoa(r.TinEye.MatchCount),
		"reverse_google":    r.ReverseURLs.GoogleLens,
		"reverse_yandex":    r.ReverseURLs.Yandex,
		"reverse_bing":      r.ReverseURLs.Bing,
		"reverse_tineye":    r.ReverseURLs.TinEyeWeb,
		"cross_session_hits": strconv.Itoa(len(r.CrossSessionHits)),
	}
	if len(r.TinEye.Matches) > 0 {
		domains := make([]string, 0, len(r.TinEye.Matches))
		for _, match := range r.TinEye.Matches {
			if match.Domain != "" {
				domains = append(domains, fmt.Sprintf("%s (%s)", match.Domain, match.CrawlDate.Format("2006-01-02")))
			}
		}
		f["tineye_domains"] = strings.Join(domains, " | ")
	}
	return f
}

// loadKey reads TINEYE_API_KEY from env and config store.
func loadKey() string {
	if v := strings.TrimSpace(os.Getenv(keyName)); v != "" {
		return v
	}
	store, err := config.NewDefaultStore()
	if err != nil {
		return ""
	}
	cfg, err := store.Load()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cfg.APIKeys[keyName])
}

func resolveThreshold() int {
	if v := strings.TrimSpace(os.Getenv(thresholdEnvKey)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	store, err := config.NewDefaultStore()
	if err != nil {
		return defaultThreshold
	}
	cfg, err := store.Load()
	if err != nil {
		return defaultThreshold
	}
	if v := strings.TrimSpace(cfg.APIKeys[thresholdEnvKey]); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return defaultThreshold
}

func defaultStoreOpener() (PhashStore, error) {
	return storage.Open("")
}
