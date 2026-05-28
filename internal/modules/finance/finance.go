package finance

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

const (
	moduleName      = "finance"
	venmoDelay      = 6 * time.Second
	batchDelay      = 2 * time.Second
	maxBodySize     = 2 * 1024 * 1024
	maxVenmoLookups = 50
)

var globalVenmoLookups int32

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type VenmoProfile struct {
	Found           bool   `json:"found"`
	DisplayName     string `json:"display_name,omitempty"`
	Username        string `json:"username,omitempty"`
	ProfilePhotoURL string `json:"profile_photo_url,omitempty"`
	Privacy         string `json:"privacy,omitempty"`
	LastTransaction string `json:"last_transaction,omitempty"`
}

type ServiceHit struct {
	Service  string `json:"service"`
	Found    bool   `json:"found"`
	NameHint string `json:"name_hint,omitempty"`
}

type FinanceResult struct {
	Found          int               `json:"found"`
	Checked        int               `json:"checked"`
	Venmo          *VenmoProfile     `json:"venmo,omitempty"`
	Services       []ServiceHit      `json:"services"`
	ByCategory     map[string]int    `json:"by_category"`
	SourceStatuses map[string]string `json:"source_statuses"`
}

type Module struct {
	httpClient     HTTPClient
	venmoLimiter   *core.RateLimiter
	batchLimiter   *core.RateLimiter
	venmoEnabled   bool
	warningPrinted bool
}

type Option func(*Module)

func New(opts ...Option) *Module {
	venmoAllowed := false
	switch strings.ToLower(strings.TrimSpace(os.Getenv("PHONEACCESS_FINANCE_VENMO"))) {
	case "1", "true", "yes", "allow":
		venmoAllowed = true
	}
	m := &Module{
		httpClient:   core.NewHTTPClient(core.DefaultHTTPTimeout),
		venmoLimiter: core.NewRateLimiter(venmoDelay),
		batchLimiter: core.NewRateLimiter(batchDelay),
		venmoEnabled: venmoAllowed,
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

func WithRateLimiters(venmo, batch time.Duration) Option {
	return func(m *Module) {
		if venmo > 0 {
			m.venmoLimiter = core.NewRateLimiter(venmo)
		}
		if batch > 0 {
			m.batchLimiter = core.NewRateLimiter(batch)
		}
	}
}

func (m *Module) Name() string {
	return moduleName
}

func (m *Module) Description() string {
	return "Silent financial-platform registration checks. Venmo phone-to-name resolution requires PHONEACCESS_FINANCE_VENMO=allow (opt-in, 50-lookup cap, 6s delay)."
}

func (m *Module) RequiresAPIKey() bool {
	return false
}

func (m *Module) Tier() core.ModuleTier {
	return core.TierActive
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
			"note":    "passive mode disables active financial platform lookups",
		},
		Evidence: []string{"Passive mode enabled; finance module made no network requests."},
	}, nil
}

func (m *Module) Run(ctx context.Context, number *core.PhoneNumber) (*core.ModuleResult, error) {
	var venmoResult *VenmoProfile
	if m.venmoEnabled {
		count := atomic.AddInt32(&globalVenmoLookups, 1)
		if count > maxVenmoLookups {
			atomic.AddInt32(&globalVenmoLookups, -1)
			venmoResult = &VenmoProfile{Found: false}
		} else {
			if !m.warningPrinted {
				_, _ = fmt.Fprintln(os.Stderr, "\x1b[33m⚠ Venmo phone lookup performs automated phone-to-name resolution.")
				_, _ = fmt.Fprintln(os.Stderr, "  This accesses public data but may violate Venmo's Terms of Service.")
				_, _ = fmt.Fprintln(os.Stderr, "  Use PHONEACCESS_FINANCE_VENMO=allow for individual investigations only.\x1b[0m")
				m.warningPrinted = true
			}
			venmoResult = m.checkVenmo(ctx, number)
		}
	}
	batchResults := m.checkBatch(ctx, number)
	aggregated := aggregate(venmoResult, batchResults)
	return &core.ModuleResult{
		ModuleName: m.Name(),
		Status:     core.ModuleStatusSuccess,
		Findings:   findingsFromFinanceResult(aggregated),
		Data:       aggregated,
		Evidence:   evidenceFromStatuses(aggregated.SourceStatuses),
	}, nil
}

func aggregate(venmo *VenmoProfile, batch []ServiceHit) FinanceResult {
	out := FinanceResult{
		Services:       make([]ServiceHit, 0),
		SourceStatuses: map[string]string{},
		ByCategory:     map[string]int{},
	}

	if venmo != nil && venmo.Found {
		out.Found++
		out.Services = append(out.Services, ServiceHit{
			Service:  "Venmo",
			Found:    true,
			NameHint: venmo.DisplayName,
		})
		out.SourceStatuses["Venmo"] = "found"
		if venmo.DisplayName != "" {
			out.ByCategory["public_profiles"]++
		}
	} else if venmo != nil {
		out.SourceStatuses["Venmo"] = "not found"
	}

	for _, hit := range batch {
		out.Checked++
		if hit.Found {
			out.Found++
			out.Services = append(out.Services, hit)
			out.SourceStatuses[hit.Service] = "registered"
			out.ByCategory["registration"]++
		} else {
			out.SourceStatuses[hit.Service] = "not found"
		}
	}

	sort.SliceStable(out.Services, func(i, j int) bool {
		if out.Services[i].Found != out.Services[j].Found {
			return out.Services[i].Found
		}
		return out.Services[i].Service < out.Services[j].Service
	})

	return out
}

func findingsFromFinanceResult(result FinanceResult) map[string]string {
	accountHits := make([]string, 0, len(result.Services))
	for _, hit := range result.Services {
		line := hit.Service
		if hit.NameHint != "" {
			line += " (" + hit.NameHint + ")"
		}
		accountHits = append(accountHits, line)
	}

	regCount := result.ByCategory["registration"]
	profCount := result.ByCategory["public_profiles"]

	return map[string]string{
		"found":              strconv.FormatBool(result.Found > 0),
		"hit_count":          strconv.Itoa(result.Found),
		"checked":            strconv.Itoa(result.Checked),
		"registration_hits":  strconv.Itoa(regCount),
		"profile_hits":       strconv.Itoa(profCount),
		"venmo_display_name": venmoName(result.Venmo),
		"venmo_username":     venmoUsername(result.Venmo),
		"venmo_privacy":      venmoPrivacy(result.Venmo),
		"venmo_profile_url":  venmoProfileURL(result.Venmo),
		"service_hits":       strings.Join(accountHits, "\n"),
		"source_statuses":    joinStatuses(result.SourceStatuses),
	}
}

func venmoName(v *VenmoProfile) string {
	if v == nil || !v.Found || v.DisplayName == "" {
		return ""
	}
	return v.DisplayName
}

func venmoUsername(v *VenmoProfile) string {
	if v == nil || !v.Found || v.Username == "" {
		return ""
	}
	return v.Username
}

func venmoPrivacy(v *VenmoProfile) string {
	if v == nil || !v.Found {
		return ""
	}
	return v.Privacy
}

func venmoProfileURL(v *VenmoProfile) string {
	if v == nil || !v.Found || v.ProfilePhotoURL == "" {
		return ""
	}
	return v.ProfilePhotoURL
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
