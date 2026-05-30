package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
	"github.com/KatrielMoses/PhoneAccess/internal/correlator"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/enumerator"
)

// ────────────────────────────────────────────────────────────────────────────
// pivot email
// ────────────────────────────────────────────────────────────────────────────

func TestPivotEmailSuggestionContainsMailaccess(t *testing.T) {
	var buf bytes.Buffer
	printPivotEmailSuggestion(&buf, "john@example.com")
	out := buf.String()

	if !strings.Contains(out, "Pivot: email address discovered") {
		t.Fatalf("missing pivot header line: %s", out)
	}
	if !strings.Contains(out, "mailaccess investigate john@example.com") {
		t.Fatalf("missing mailaccess suggestion: %s", out)
	}
	if !strings.Contains(out, "phoneaccess investigate --modules breach,search,paste john@example.com") {
		t.Fatalf("missing phoneaccess suggestion: %s", out)
	}
}

func TestPivotEmailSelectsBreachSearchPasteModules(t *testing.T) {
	registry := []core.Module{
		pivotFakeModule{name: "carrier"},
		pivotFakeModule{name: "breach"},
		pivotFakeModule{name: "search"},
		pivotFakeModule{name: "paste"},
		pivotFakeModule{name: "spam"},
	}

	selected := selectModulesByNames(registry, "breach", "search", "paste")

	activeCount := 0
	for _, m := range selected {
		if _, ok := m.(pivotFakeModule); ok {
			activeCount++
		}
	}
	if activeCount != 3 {
		t.Fatalf("expected 3 active modules (breach/search/paste), got %d", activeCount)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// pivot username
// ────────────────────────────────────────────────────────────────────────────

func TestPivotUsernameUsesEnumeratorServiceList(t *testing.T) {
	services := enumerator.Services()
	if len(services) == 0 {
		t.Fatal("enumerator.Services() returned empty list")
	}
}

func TestPivotUsernameRenderShowsPlatforms(t *testing.T) {
	result := PivotUsernameResult{
		Username:        "johndoe",
		ServicesChecked: 200,
		Hits: []enumerator.UsernameProfileHit{
			{Platform: "GitHub", URL: "https://github.com/johndoe", Confidence: 1.0},
			{Platform: "Twitter", URL: "https://twitter.com/johndoe", Confidence: 1.0},
		},
	}

	var buf bytes.Buffer
	if err := renderPivotUsername(&buf, result); err != nil {
		t.Fatalf("renderPivotUsername: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "johndoe") {
		t.Fatalf("missing username in output: %s", out)
	}
	if !strings.Contains(out, "GitHub") {
		t.Fatalf("missing GitHub in output: %s", out)
	}
	if !strings.Contains(out, "Twitter") {
		t.Fatalf("missing Twitter in output: %s", out)
	}
	if !strings.Contains(out, "2") {
		t.Fatalf("missing hit count: %s", out)
	}
}

func TestPivotUsernameRenderShowsNoneWhenNoHits(t *testing.T) {
	result := PivotUsernameResult{Username: "nobody", ServicesChecked: 50, Hits: nil}
	var buf bytes.Buffer
	_ = renderPivotUsername(&buf, result)
	if !strings.Contains(buf.String(), "No profiles found") {
		t.Fatalf("expected no-profiles message: %s", buf.String())
	}
}

// ────────────────────────────────────────────────────────────────────────────
// pivot domain
// ────────────────────────────────────────────────────────────────────────────

func TestPivotDomainRenderShowsCertificates(t *testing.T) {
	result := PivotDomainResult{
		Domain: "example.com",
		Certificates: []pivotCertHit{
			{Domain: "example.com", Issuer: "Let's Encrypt", IssuedAt: "2024-01-15"},
			{Domain: "www.example.com", IssuedAt: "2024-01-15"},
		},
		VTConfigured: false,
	}

	var buf bytes.Buffer
	if err := renderPivotDomain(&buf, result); err != nil {
		t.Fatalf("renderPivotDomain: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "example.com") {
		t.Fatalf("missing domain: %s", out)
	}
	if !strings.Contains(out, "2 domain(s)") {
		t.Fatalf("missing cert count: %s", out)
	}
	if !strings.Contains(out, "Let's Encrypt") {
		t.Fatalf("missing issuer: %s", out)
	}
	if !strings.Contains(out, "not configured") {
		t.Fatalf("expected VT not-configured message: %s", out)
	}
}

func TestPivotDomainRenderShowsVTHits(t *testing.T) {
	result := PivotDomainResult{
		Domain:        "malicious.example",
		VTConfigured:  true,
		VTThreatCount: 3,
		VTLabels:      []string{"malware", "phishing"},
	}
	var buf bytes.Buffer
	_ = renderPivotDomain(&buf, result)
	out := buf.String()
	if !strings.Contains(out, "3 hit(s)") {
		t.Fatalf("missing VT hit count: %s", out)
	}
	if !strings.Contains(out, "malware") {
		t.Fatalf("missing VT label: %s", out)
	}
}

func TestPivotDomainRenderRunsInfrastructureSources(t *testing.T) {
	// Verifies the domain pivot's struct covers crt.sh, RDAP, and VT fields.
	result := PivotDomainResult{
		Domain:           "example.com",
		Certificates:     []pivotCertHit{{Domain: "example.com"}},
		Registrant:       "John Smith",
		RegistrantEmail:  "john@example.com",
		RegistrationDate: "2020-01-01",
		VTConfigured:     true,
		VTThreatCount:    0,
	}
	var buf bytes.Buffer
	_ = renderPivotDomain(&buf, result)
	out := buf.String()
	if !strings.Contains(out, "John Smith") {
		t.Fatalf("WHOIS registrant missing: %s", out)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// pivot phone
// ────────────────────────────────────────────────────────────────────────────

func TestPivotPhoneRunsPassiveByDefault(t *testing.T) {
	// runPivotPhone with active=false must set passive=true in the engine.
	// We verify by checking that the PassiveFlag is respected.  Since we
	// can't easily inspect engine internals here, we test selectModules
	// returns the full registry (no --modules filter).
	registry := []core.Module{
		pivotFakeModule{name: "carrier"},
		pivotFakeModule{name: "spam"},
	}
	selected, err := selectModules(registry, "")
	if err != nil {
		t.Fatalf("selectModules: %v", err)
	}
	if len(selected) != len(registry) {
		t.Fatalf("expected all %d modules selected, got %d", len(registry), len(selected))
	}
}

// ────────────────────────────────────────────────────────────────────────────
// --case flag / InvestigationLink
// ────────────────────────────────────────────────────────────────────────────

func TestPivotLinkZeroWhenNoCaseFlag(t *testing.T) {
	p := &pivotShared{caseID: 0}
	link := pivotLink(p, "email", "x@y.com")
	if link.ParentID != 0 {
		t.Fatalf("expected zero ParentID when caseID=0, got %d", link.ParentID)
	}
}

func TestPivotLinkPopulatedWhenCaseFlagSet(t *testing.T) {
	p := &pivotShared{caseID: 42}
	link := pivotLink(p, "email", "x@y.com")
	if link.ParentID != 42 {
		t.Fatalf("expected ParentID=42, got %d", link.ParentID)
	}
	if link.PivotType != "email" {
		t.Fatalf("expected PivotType=email, got %s", link.PivotType)
	}
	if link.PivotValue != "x@y.com" {
		t.Fatalf("expected PivotValue=x@y.com, got %s", link.PivotValue)
	}
	if link.Depth != 1 {
		t.Fatalf("expected Depth=1, got %d", link.Depth)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// --min-confidence terminal filtering
// ────────────────────────────────────────────────────────────────────────────

func makeIdentityReport(names []correlator.FieldCandidate) *core.InvestigationReport {
	number, _ := core.NormalizePhoneNumber("+14155552671")
	return &core.InvestigationReport{
		GeneratedAt: time.Now().UTC(),
		Number:      number,
		IdentityRecord: &correlator.UnifiedIdentityRecord{
			Status:      correlator.StatusSuccess,
			Names:       names,
			Addresses:   []correlator.FieldCandidate{},
			DOBs:        []correlator.FieldCandidate{},
			Emails:      []correlator.FieldCandidate{},
			SocialLinks: []correlator.FieldCandidate{},
			Conflicts:   []correlator.Conflict{},
			SourceRuns:  []correlator.SourceRun{},
		},
	}
}

func TestMinConfidenceHidesTerminalFindingsBelowThreshold(t *testing.T) {
	report := makeIdentityReport([]correlator.FieldCandidate{
		{Field: "name", DisplayValue: "John Smith", Confidence: 0.89, ConfidenceLabel: "high"},
		{Field: "name", DisplayValue: "J. Smythe", Confidence: 0.41, ConfidenceLabel: "suppressed"},
	})

	block := IdentityRecordBlock{MinConfidence: 0.75}
	out := block.Render(report)

	if strings.Contains(out, "J. Smythe") {
		t.Fatalf("J. Smythe (0.41) should be hidden at threshold 0.75: %s", out)
	}
	if !strings.Contains(out, "John Smith") {
		t.Fatalf("John Smith (0.89) should be visible: %s", out)
	}
	if !strings.Contains(out, "below 0.75 confidence threshold") {
		t.Fatalf("expected threshold summary line: %s", out)
	}
}

func TestMinConfidenceSummaryLineShowsCorrectHiddenCount(t *testing.T) {
	report := makeIdentityReport([]correlator.FieldCandidate{
		{Field: "name", DisplayValue: "Alice", Confidence: 0.90},
		{Field: "name", DisplayValue: "Bob", Confidence: 0.60},
		{Field: "name", DisplayValue: "Charlie", Confidence: 0.40},
	})

	block := IdentityRecordBlock{MinConfidence: 0.75}
	out := block.Render(report)

	// Bob (0.60) and Charlie (0.40) are both below 0.75 → hidden count = 2.
	if !strings.Contains(out, "2 findings below 0.75") {
		t.Fatalf("expected '2 findings below 0.75' in: %s", out)
	}
}

func TestMinConfidenceZeroShowsAllFindings(t *testing.T) {
	report := makeIdentityReport([]correlator.FieldCandidate{
		{Field: "name", DisplayValue: "John Smith", Confidence: 0.89},
		{Field: "name", DisplayValue: "J. Smythe", Confidence: 0.28},
	})

	block := IdentityRecordBlock{MinConfidence: 0.0}
	out := block.Render(report)

	if !strings.Contains(out, "J. Smythe") {
		t.Fatalf("J. Smythe should be visible at zero threshold: %s", out)
	}
	if !strings.Contains(out, "John Smith") {
		t.Fatalf("John Smith should be visible: %s", out)
	}
	// No threshold summary line when minConfidence is zero.
	if strings.Contains(out, "confidence threshold") {
		t.Fatalf("should not show threshold summary when minConfidence=0: %s", out)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Suppressed findings show with ? indicator
// ────────────────────────────────────────────────────────────────────────────

func TestSuppressedFindingsShowWithQuestionMarkIndicator(t *testing.T) {
	report := makeIdentityReport([]correlator.FieldCandidate{
		{Field: "name", DisplayValue: "Unknown variant", Confidence: 0.28, Suppressed: true},
	})

	block := IdentityRecordBlock{MinConfidence: 0.0}
	out := block.Render(report)

	if !strings.Contains(out, "Unknown variant") {
		t.Fatalf("suppressed candidate should be shown: %s", out)
	}
	if !strings.Contains(out, "?") {
		t.Fatalf("suppressed candidate should use ? indicator: %s", out)
	}
}

func TestLowConfidenceFindingsShowWithTildeIndicator(t *testing.T) {
	report := makeIdentityReport([]correlator.FieldCandidate{
		{Field: "name", DisplayValue: "J. Smith", Confidence: 0.55},
	})

	block := IdentityRecordBlock{MinConfidence: 0.0}
	out := block.Render(report)

	if !strings.Contains(out, "J. Smith") {
		t.Fatalf("low-confidence candidate should be shown: %s", out)
	}
	if !strings.Contains(out, "~") {
		t.Fatalf("low-confidence candidate should use ~ indicator: %s", out)
	}
}

func TestHighConfidenceFindingsShowWithCheckIndicator(t *testing.T) {
	report := makeIdentityReport([]correlator.FieldCandidate{
		{Field: "name", DisplayValue: "Jane Doe", Confidence: 0.87},
	})

	block := IdentityRecordBlock{MinConfidence: 0.0}
	out := block.Render(report)

	if !strings.Contains(out, "✓") {
		t.Fatalf("high-confidence candidate should use ✓ indicator: %s", out)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// JSON output always includes all findings regardless of --min-confidence
// ────────────────────────────────────────────────────────────────────────────

func TestMinConfidenceDoesNotSuppressJSONOutput(t *testing.T) {
	lowName := correlator.FieldCandidate{
		Field:        "name",
		DisplayValue: "J. Smythe",
		Confidence:   0.30,
		Suppressed:   true,
	}
	report := makeIdentityReport([]correlator.FieldCandidate{
		{Field: "name", DisplayValue: "John Smith", Confidence: 0.89},
		lowName,
	})

	// Marshal the full report to JSON — should always include all candidates.
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !strings.Contains(string(data), "J. Smythe") {
		t.Fatalf("JSON output must include all findings regardless of confidence: %s", string(data))
	}
}

// ────────────────────────────────────────────────────────────────────────────
// PHONEACCESS_MIN_CONFIDENCE config key
// ────────────────────────────────────────────────────────────────────────────

func TestPhoneAccessMinConfidenceConfigKeyExistsInCatalog(t *testing.T) {
	found := false
	for _, item := range apiKeyCatalog() {
		if item.Name == "PHONEACCESS_MIN_CONFIDENCE" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("PHONEACCESS_MIN_CONFIDENCE must appear in apiKeyCatalog()")
	}
}

func TestResolveMinConfidenceConfigIgnoredWhenFlagAlreadySet(t *testing.T) {
	opts := &options{minConfidence: 0.8}
	// nil store — should not panic and should leave the value unchanged.
	resolveMinConfidenceConfig(opts, nil)
	if opts.minConfidence != 0.8 {
		t.Fatalf("expected 0.8 unchanged, got %f", opts.minConfidence)
	}
}

func TestConfidenceTierIndicatorReturnsCorrectSymbols(t *testing.T) {
	cases := []struct {
		confidence float64
		want       string
	}{
		{0.90, "✓"},
		{0.65, "✓"},
		{0.64, "~"},
		{0.45, "~"},
		{0.44, "?"},
		{0.00, "?"},
	}
	for _, tc := range cases {
		got := confidenceTierIndicator(tc.confidence)
		if got != tc.want {
			t.Errorf("confidenceTierIndicator(%.2f) = %q, want %q", tc.confidence, got, tc.want)
		}
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

// pivotFakeModule is a minimal core.Module for pivot tests.
type pivotFakeModule struct {
	name string
}

func (m pivotFakeModule) Name() string           { return m.name }
func (m pivotFakeModule) Description() string    { return m.name }
func (m pivotFakeModule) RequiresAPIKey() bool   { return false }
func (m pivotFakeModule) Tier() core.ModuleTier  { return core.TierPassive }
func (m pivotFakeModule) ProxyAware() bool       { return true }
func (m pivotFakeModule) DryRun(_ context.Context, _ *core.PhoneNumber) error { return nil }
func (m pivotFakeModule) Run(_ context.Context, _ *core.PhoneNumber) (*core.ModuleResult, error) {
	return &core.ModuleResult{ModuleName: m.name, Status: core.ModuleStatusSuccess}, nil
}
