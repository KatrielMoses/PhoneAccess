package intelligence

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

const moduleName = "intelligence"

// HTTPClient is satisfied by *http.Client and test doubles.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// SanctionsHit is a single hit from a sanctions/PEP database.
type SanctionsHit struct {
	EntityID    string   `json:"entity_id"`
	Name        string   `json:"entity_name"`
	Datasets    []string `json:"datasets"`
	Score       float64  `json:"score"`
	Position    string   `json:"position,omitempty"`
	Nationality string   `json:"nationality,omitempty"`
	BirthDate   string   `json:"birth_date,omitempty"`
}

// SanctionsResult is the aggregated output of the sanctions screen.
type SanctionsResult struct {
	Screened     bool           `json:"screened"`
	Hits         []SanctionsHit `json:"hits,omitempty"`
	ListsChecked []string       `json:"lists_checked"`
	HighRisk     bool           `json:"high_risk"`
}

// MediaArticle is a single adverse-media article.
type MediaArticle struct {
	Title       string    `json:"title"`
	URL         string    `json:"url"`
	Source      string    `json:"source"`
	PublishedAt time.Time `json:"published_at"`
	Snippet     string    `json:"snippet,omitempty"`
	Keywords    []string  `json:"keywords,omitempty"`
}

// MediaResult is the aggregated output of the adverse-media screen.
type MediaResult struct {
	ArticleCount int            `json:"article_count"`
	Articles     []MediaArticle `json:"articles,omitempty"`
	RiskKeywords []string       `json:"risk_keywords,omitempty"`
	Sources      []string       `json:"sources,omitempty"`
}

// IntelligenceResult combines sanctions and adverse media screening.
type IntelligenceResult struct {
	Sanctions SanctionsResult `json:"sanctions"`
	Media     MediaResult     `json:"media"`
}

// Module implements intelligence screening.
type Module struct {
	httpClient   HTTPClient
	mediaLimiter *core.RateLimiter
}

// Option configures a Module.
type Option func(*Module)

// New constructs a Module with default settings.
func New(opts ...Option) *Module {
	m := &Module{
		httpClient:   core.NewHTTPClient(core.DefaultHTTPTimeout),
		mediaLimiter: core.NewRateLimiter(3 * time.Second),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// WithHTTPClient replaces the HTTP client (for testing).
func WithHTTPClient(client HTTPClient) Option {
	return func(m *Module) {
		if client != nil {
			m.httpClient = client
		}
	}
}

// WithMediaRateLimiter sets the inter-query delay for the media source.
func WithMediaRateLimiter(d time.Duration) Option {
	return func(m *Module) {
		m.mediaLimiter = core.NewRateLimiter(d)
	}
}

func (m *Module) Name() string { return moduleName }
func (m *Module) Description() string {
	return "Sanctions/PEP screening via OpenSanctions (OFAC, UN, EU, UK HMT, 100+ official sources) and adverse media via Google News RSS. Requires --active."
}
func (m *Module) RequiresAPIKey() bool  { return false }
func (m *Module) Tier() core.ModuleTier { return core.TierActive }
func (m *Module) ProxyAware() bool      { return true }

func (m *Module) DryRun(ctx context.Context, number *core.PhoneNumber) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (m *Module) Run(ctx context.Context, number *core.PhoneNumber) (*core.ModuleResult, error) {
	var (
		sanctionsResult SanctionsResult
		mediaResult     MediaResult
		wg              sync.WaitGroup
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		sanctionsResult = m.fetchSanctions(ctx, number)
	}()
	go func() {
		defer wg.Done()
		mediaResult = m.fetchMedia(ctx, number)
	}()
	wg.Wait()

	intel := IntelligenceResult{
		Sanctions: sanctionsResult,
		Media:     mediaResult,
	}

	return &core.ModuleResult{
		ModuleName: m.Name(),
		Status:     core.ModuleStatusSuccess,
		Findings:   findingsFromIntelligence(intel),
		Data:       intel,
		Evidence:   evidenceFromIntelligence(intel),
	}, nil
}

func findingsFromIntelligence(intel IntelligenceResult) map[string]string {
	hitCount := len(intel.Sanctions.Hits)
	findings := map[string]string{
		"sanctions_screened":  strconv.FormatBool(intel.Sanctions.Screened),
		"sanctions_hit_count": strconv.Itoa(hitCount),
		"sanctions_high_risk": strconv.FormatBool(intel.Sanctions.HighRisk),
		"media_article_count": strconv.Itoa(intel.Media.ArticleCount),
	}

	if len(intel.Sanctions.ListsChecked) > 0 {
		findings["sanctions_lists_checked"] = strings.Join(intel.Sanctions.ListsChecked, ", ")
	}

	if hitCount > 0 {
		names := make([]string, 0, hitCount)
		for _, hit := range intel.Sanctions.Hits {
			names = append(names, hit.Name)
		}
		findings["entity_names"] = strings.Join(names, "; ")
		findings["sanctions_hit"] = "true"
	}

	if len(intel.Media.RiskKeywords) > 0 {
		findings["media_risk_keywords"] = strings.Join(intel.Media.RiskKeywords, ", ")
	}

	return findings
}

func evidenceFromIntelligence(intel IntelligenceResult) []string {
	evidence := make([]string, 0)
	for _, hit := range intel.Sanctions.Hits {
		evidence = append(evidence, fmt.Sprintf("Sanctions hit: %s [%s] score %.2f",
			hit.Name, strings.Join(hit.Datasets, ", "), hit.Score))
	}
	for _, article := range intel.Media.Articles {
		evidence = append(evidence, article.URL)
	}
	return evidence
}
