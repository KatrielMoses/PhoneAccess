package infrastructure

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
	"golang.org/x/sync/errgroup"
)

const moduleName = "infrastructure"

// HTTPClient is satisfied by *http.Client and test doubles.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// CertHit holds a domain discovered via SSL certificate transparency.
type CertHit struct {
	Domain         string `json:"domain"`
	Issuer         string `json:"issuer,omitempty"`
	IssuedAt       string `json:"issued_at,omitempty"`
	ExpiresAt      string `json:"expires_at,omitempty"`
	EntryTimestamp string `json:"entry_timestamp,omitempty"`
}

// WhoisHit holds registrant contact data found in a domain WHOIS/RDAP record.
type WhoisHit struct {
	Domain           string `json:"domain"`
	RegistrantName   string `json:"registrant_name,omitempty"`
	RegistrantOrg    string `json:"registrant_org,omitempty"`
	RegistrantEmail  string `json:"registrant_email,omitempty"`
	RegistrationDate string `json:"registration_date,omitempty"`
	ExpiryDate       string `json:"expiry_date,omitempty"`
}

// VTHit holds VirusTotal cross-reference results.
type VTHit struct {
	Query             string   `json:"query"`
	HitCount          int      `json:"hit_count"`
	ThreatLabels      []string `json:"threat_labels,omitempty"`
	AssociatedDomains []string `json:"associated_domains,omitempty"`
	AssociatedIPs     []string `json:"associated_ips,omitempty"`
}

// MalwareHit holds a malware sample from MalwareBazaar referencing the number.
type MalwareHit struct {
	SHA256          string   `json:"sha256"`
	FileType        string   `json:"file_type,omitempty"`
	Signature       string   `json:"signature,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	MalwareFamilies []string `json:"malware_families,omitempty"`
}

// InfrastructureResult is the typed result stored in ModuleResult.Data.
type InfrastructureResult struct {
	CertHits        []CertHit    `json:"cert_hits"`
	WhoisHits       []WhoisHit   `json:"whois_hits"`
	VirusTotalHits  []VTHit      `json:"virustotal_hits"`
	MalwareHits     []MalwareHit `json:"malware_hits"`
	SourcesChecked  []string     `json:"sources_checked"`
	SourcesWithHits []string     `json:"sources_with_hits"`
	VTConfigured    bool         `json:"vt_configured"`
}

// exactLimiter enforces a minimum gap between calls with no jitter.
type exactLimiter struct {
	mu       sync.Mutex
	lastSeen time.Time
	delay    time.Duration
}

func newExactLimiter(delay time.Duration) *exactLimiter {
	return &exactLimiter{delay: delay}
}

func (l *exactLimiter) Wait(ctx context.Context) error {
	if l == nil || l.delay <= 0 {
		return nil
	}
	for {
		l.mu.Lock()
		now := time.Now()
		wait := l.delay - now.Sub(l.lastSeen)
		if wait <= 0 {
			l.lastSeen = now
			l.mu.Unlock()
			return nil
		}
		l.mu.Unlock()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// Module implements core.Module for infrastructure intelligence.
type Module struct {
	httpClient  HTTPClient
	crtLimiter  *core.RateLimiter
	rdapLimiter *core.RateLimiter
	mbLimiter   *core.RateLimiter
	vtLimiter   *exactLimiter

	bootstrapMu   sync.Mutex
	bootstrapData map[string]string // TLD -> RDAP base URL
	bootstrapDone bool
	bootstrapErr  error
}

// Option configures a Module.
type Option func(*Module)

// New returns a Module wired with production defaults.
func New(opts ...Option) *Module {
	m := &Module{
		httpClient:  core.NewHTTPClient(core.DefaultHTTPTimeout),
		crtLimiter:  core.NewRateLimiter(2 * time.Second),
		rdapLimiter: core.NewRateLimiter(3 * time.Second),
		mbLimiter:   core.NewRateLimiter(2 * time.Second),
		vtLimiter:   newExactLimiter(15 * time.Second),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// WithHTTPClient overrides the HTTP client (for testing).
func WithHTTPClient(client HTTPClient) Option {
	return func(m *Module) {
		if client != nil {
			m.httpClient = client
		}
	}
}

// WithCRTDelay overrides the crt.sh inter-request delay (for testing).
func WithCRTDelay(d time.Duration) Option {
	return func(m *Module) { m.crtLimiter = core.NewRateLimiter(d) }
}

// WithRDAPDelay overrides the RDAP inter-request delay (for testing).
func WithRDAPDelay(d time.Duration) Option {
	return func(m *Module) { m.rdapLimiter = core.NewRateLimiter(d) }
}

// WithVTDelay overrides the VirusTotal inter-request delay (for testing).
func WithVTDelay(d time.Duration) Option {
	return func(m *Module) { m.vtLimiter = newExactLimiter(d) }
}

// WithMBDelay overrides the MalwareBazaar inter-request delay (for testing).
func WithMBDelay(d time.Duration) Option {
	return func(m *Module) { m.mbLimiter = core.NewRateLimiter(d) }
}

// WithBootstrapData pre-seeds the RDAP bootstrap cache (for testing).
func WithBootstrapData(data map[string]string) Option {
	return func(m *Module) {
		m.bootstrapMu.Lock()
		m.bootstrapData = data
		m.bootstrapDone = true
		m.bootstrapMu.Unlock()
	}
}

func (m *Module) Name() string        { return moduleName }
func (m *Module) ProxyAware() bool    { return true }
func (m *Module) RequiresAPIKey() bool { return false }
func (m *Module) Tier() core.ModuleTier { return core.TierActive }

func (m *Module) Description() string {
	return "SSL certificate transparency, WHOIS/RDAP correlation, VirusTotal, and MalwareBazaar cross-reference."
}

func (m *Module) DryRun(ctx context.Context, number *core.PhoneNumber) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (m *Module) Run(ctx context.Context, number *core.PhoneNumber) (*core.ModuleResult, error) {
	vtKey := core.GetAPIKey(ctx, "VIRUSTOTAL_API_KEY")

	result := InfrastructureResult{
		CertHits:        []CertHit{},
		WhoisHits:       []WhoisHit{},
		VirusTotalHits:  []VTHit{},
		MalwareHits:     []MalwareHit{},
		VTConfigured:    vtKey != "",
	}

	// domainsCh carries discovered domains from crt.sh to the WHOIS goroutine.
	domainsCh := make(chan []string, 1)

	var (
		certHits    []CertHit
		whoisHits   []WhoisHit
		vtHit       *VTHit
		malwareHits []MalwareHit
		mu          sync.Mutex
	)

	g, gctx := errgroup.WithContext(ctx)

	// crt.sh — queries each format variant and sends discovered domains downstream.
	g.Go(func() error {
		hits, domains := m.queryCRT(gctx, number)
		domainsCh <- domains
		mu.Lock()
		certHits = hits
		mu.Unlock()
		return nil
	})

	// RDAP/WHOIS — waits for domains from crt.sh, then queries each one.
	g.Go(func() error {
		var domains []string
		select {
		case domains = <-domainsCh:
		case <-gctx.Done():
			return nil
		}
		hits := m.queryRDAP(gctx, domains)
		mu.Lock()
		whoisHits = hits
		mu.Unlock()
		return nil
	})

	// VirusTotal — skipped when key is absent.
	g.Go(func() error {
		if vtKey == "" {
			return nil
		}
		hit := m.queryVT(gctx, number, vtKey)
		mu.Lock()
		vtHit = hit
		mu.Unlock()
		return nil
	})

	// MalwareBazaar — always runs.
	g.Go(func() error {
		hits := m.queryMalwareBazaar(gctx, number)
		mu.Lock()
		malwareHits = hits
		mu.Unlock()
		return nil
	})

	_ = g.Wait()

	if certHits != nil {
		result.CertHits = certHits
	}
	if whoisHits != nil {
		result.WhoisHits = whoisHits
	}
	if malwareHits != nil {
		result.MalwareHits = malwareHits
	}

	sourcesChecked := []string{"crt.sh", "RDAP/WHOIS", "MalwareBazaar"}
	sourcesWithHits := []string{}

	if len(certHits) > 0 {
		sourcesWithHits = append(sourcesWithHits, "crt.sh")
	}
	if len(whoisHits) > 0 {
		sourcesWithHits = append(sourcesWithHits, "RDAP/WHOIS")
	}
	if len(malwareHits) > 0 {
		sourcesWithHits = append(sourcesWithHits, "MalwareBazaar")
	}

	if vtKey != "" {
		sourcesChecked = append(sourcesChecked, "VirusTotal")
		if vtHit != nil {
			result.VirusTotalHits = []VTHit{*vtHit}
			sourcesWithHits = append(sourcesWithHits, "VirusTotal")
		}
	}

	result.SourcesChecked = sourcesChecked
	result.SourcesWithHits = sourcesWithHits

	findings := findingsFromResult(result)
	return &core.ModuleResult{
		ModuleName: m.Name(),
		Status:     core.ModuleStatusSuccess,
		Findings:   findings,
		Data:       result,
		Evidence:   evidenceLines(result),
	}, nil
}

func findingsFromResult(r InfrastructureResult) map[string]string {
	// Collect unique cert domains for the identity graph.
	domainSet := map[string]bool{}
	for _, hit := range r.CertHits {
		if hit.Domain != "" {
			domainSet[hit.Domain] = true
		}
	}

	nameSet := map[string]bool{}
	emailSet := map[string]bool{}
	for _, hit := range r.WhoisHits {
		if hit.RegistrantName != "" {
			nameSet[hit.RegistrantName] = true
		}
		if hit.RegistrantEmail != "" {
			emailSet[hit.RegistrantEmail] = true
		}
	}

	vtHitCount := 0
	var vtLabels []string
	for _, hit := range r.VirusTotalHits {
		vtHitCount += hit.HitCount
		vtLabels = append(vtLabels, hit.ThreatLabels...)
	}

	var malwareFamilies []string
	for _, hit := range r.MalwareHits {
		malwareFamilies = append(malwareFamilies, hit.MalwareFamilies...)
	}

	return map[string]string{
		"cert_domain_count":    strconv.Itoa(len(domainSet)),
		"discovered_domains":   strings.Join(sortedKeys(domainSet), ", "),
		"whois_hit_count":      strconv.Itoa(len(r.WhoisHits)),
		"registrant_names":     strings.Join(sortedKeys(nameSet), ", "),
		"registrant_emails":    strings.Join(sortedKeys(emailSet), ", "),
		"vt_hit_count":         strconv.Itoa(vtHitCount),
		"vt_threat_labels":     strings.Join(dedupeStrings(vtLabels), ", "),
		"malware_sample_count": strconv.Itoa(len(r.MalwareHits)),
		"malware_families":     strings.Join(dedupeStrings(malwareFamilies), ", "),
		"sources_checked":      strings.Join(r.SourcesChecked, ", "),
		"sources_with_hits":    strings.Join(r.SourcesWithHits, ", "),
		"vt_configured":        strconv.FormatBool(r.VTConfigured),
	}
}

func evidenceLines(r InfrastructureResult) []string {
	var lines []string
	for _, src := range r.SourcesChecked {
		hit := false
		for _, h := range r.SourcesWithHits {
			if h == src {
				hit = true
				break
			}
		}
		status := "no results"
		if hit {
			status = "hit"
		}
		if src == "VirusTotal" && !r.VTConfigured {
			status = "skipped (no key)"
		}
		lines = append(lines, src+": "+status)
	}
	return lines
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func dedupeStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
