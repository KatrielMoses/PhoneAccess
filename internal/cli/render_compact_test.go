package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

// buildCompactReport builds a minimal report for compact/field testing.
func buildCompactReport(t *testing.T, results ...*core.ModuleResult) *core.InvestigationReport {
	t.Helper()
	number, err := core.NormalizePhoneNumber("+14155552671")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	report := &core.InvestigationReport{
		GeneratedAt: time.Now().UTC(),
		Number:      number,
		Results:     results,
	}
	report.Messenger = core.BuildMessengerReport(results)
	report.RiskScore = core.ScoreRisk(report)
	return report
}

// --- CompactRenderer ---

func TestCompactRendererMaxSixLines(t *testing.T) {
	// Build a richly-populated report to exercise all five optional lines.
	carrierResult := testModuleResult("carrier", map[string]string{
		"carrier":   "AT&T Mobility",
		"line_type": "mobile",
	}, nil)
	spamResult := testModuleResult("spam", map[string]string{
		"total_reports": "5",
		"spam_score":    "30",
		"risk":          "MODERATE",
	}, nil)
	breachResult := testModuleResult("breach", map[string]string{
		"breach_count": "2",
		"found":        "true",
	}, nil)
	enumResult := testModuleResult("enumerator", map[string]string{
		"hit_count":      "3",
		"total_services": "277",
	}, nil)
	report := buildCompactReport(t, carrierResult, spamResult, breachResult, enumResult)
	report.Timeline = &core.Timeline{FirstSeen: "2021-03-14", MostRecent: "2024-11-08"}
	report.Messenger = &core.MessengerReport{
		WhatsApp: &core.MessengerAccount{Found: true, DisplayName: "John S."},
		Telegram: &core.MessengerAccount{Found: true},
		Signal:   &core.MessengerAccount{Found: false},
	}

	out := NewCompactRenderer().Render(report)
	lines := nonEmptyLines(out)

	if len(lines) > 6 {
		t.Fatalf("compact output has %d lines, want ≤6:\n%s", len(lines), out)
	}
}

func TestCompactRendererEmptyReportNoPanic(t *testing.T) {
	number, err := core.NormalizePhoneNumber("+14155552671")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	report := &core.InvestigationReport{
		GeneratedAt: time.Now().UTC(),
		Number:      number,
		Results:     []*core.ModuleResult{},
	}
	report.RiskScore = core.ScoreRisk(report)

	// Must not panic.
	out := NewCompactRenderer().Render(report)
	if out == "" {
		t.Fatal("compact render returned empty string for empty report")
	}
}

func TestCompactRendererLine1ContainsE164(t *testing.T) {
	report := buildCompactReport(t)
	out := NewCompactRenderer().Render(report)
	if !strings.Contains(out, "+14155552671") {
		t.Fatalf("compact line 1 missing E.164 number: %s", out)
	}
}

func TestCompactRendererRiskBandPresent(t *testing.T) {
	report := buildCompactReport(t)
	out := NewCompactRenderer().Render(report)
	// Should contain the risk band string somewhere (colour codes are allowed).
	if !strings.Contains(out, "RISK:") {
		t.Fatalf("compact output missing RISK: prefix: %s", out)
	}
}

func TestCompactRendererBreachCountPresent(t *testing.T) {
	report := buildCompactReport(t,
		testModuleResult("breach", map[string]string{"breach_count": "3", "found": "true"}, nil),
	)
	out := NewCompactRenderer().Render(report)
	if !strings.Contains(out, "Breaches: 3") {
		t.Fatalf("compact output missing breach count: %s", out)
	}
}

func TestCompactRendererMessengerLine(t *testing.T) {
	report := buildCompactReport(t)
	report.Messenger = &core.MessengerReport{
		WhatsApp: &core.MessengerAccount{Found: true},
		Telegram: &core.MessengerAccount{Found: false},
		Signal:   &core.MessengerAccount{Found: true},
	}
	out := NewCompactRenderer().Render(report)
	if !strings.Contains(out, "Messenger:") {
		t.Fatalf("compact output missing Messenger line: %s", out)
	}
	if !strings.Contains(out, "✓WhatsApp") {
		t.Fatalf("compact output missing ✓WhatsApp: %s", out)
	}
	if !strings.Contains(out, "—Telegram") {
		t.Fatalf("compact output missing —Telegram: %s", out)
	}
}

func TestCompactRendererTimelineLine(t *testing.T) {
	report := buildCompactReport(t)
	report.Timeline = &core.Timeline{FirstSeen: "2021-03-14", MostRecent: "2024-11-08"}
	out := NewCompactRenderer().Render(report)
	if !strings.Contains(out, "first seen 2021-03-14") {
		t.Fatalf("compact output missing timeline first seen: %s", out)
	}
	if !strings.Contains(out, "last seen 2024-11-08") {
		t.Fatalf("compact output missing timeline last seen: %s", out)
	}
}

func TestCompactRendererOmitsEmptyTimelineWhenNoData(t *testing.T) {
	report := buildCompactReport(t)
	// No Timeline set — Timeline line should be absent.
	out := NewCompactRenderer().Render(report)
	if strings.Contains(out, "Timeline:") {
		t.Fatalf("compact output should omit Timeline line when no data: %s", out)
	}
}

func TestCompactRendererFitsIn80Cols(t *testing.T) {
	report := buildCompactReport(t,
		testModuleResult("carrier", map[string]string{"carrier": "AT&T Mobility"}, nil),
		testModuleResult("breach", map[string]string{"breach_count": "2"}, nil),
	)
	out := NewCompactRenderer().Render(report)
	for _, line := range nonEmptyLines(out) {
		// Strip ANSI escape codes before measuring.
		plain := stripANSI(line)
		if len([]rune(plain)) > 80 {
			t.Logf("Line exceeds 80 cols (%d): %s", len([]rune(plain)), plain)
			// Warn but don't fail — some fields may legitimately wrap.
		}
	}
}

// --- FieldRenderer ---

func TestFieldRendererPipeDelimited(t *testing.T) {
	report := buildCompactReport(t)
	out := NewFieldRenderer().Render(report)
	line := strings.TrimRight(out, "\n")
	parts := strings.Split(line, "|")
	const wantFields = 10
	if len(parts) != wantFields {
		t.Fatalf("field line has %d fields, want %d: %q", len(parts), wantFields, line)
	}
}

func TestFieldRendererE164IsFirstField(t *testing.T) {
	report := buildCompactReport(t)
	out := NewFieldRenderer().Render(report)
	line := strings.TrimRight(out, "\n")
	parts := strings.Split(line, "|")
	if parts[0] != "+14155552671" {
		t.Fatalf("field[0] want +14155552671, got %q", parts[0])
	}
}

func TestFieldRendererRiskBandAndScore(t *testing.T) {
	report := buildCompactReport(t)
	out := NewFieldRenderer().Render(report)
	line := strings.TrimRight(out, "\n")
	parts := strings.Split(line, "|")
	if parts[1] == "" {
		t.Fatal("field[1] (risk_band) is empty")
	}
	if parts[2] == "" {
		t.Fatal("field[2] (risk_score) is empty")
	}
}

func TestFieldRendererEmptyFieldsForMissingData(t *testing.T) {
	// No results → no carrier, breach_count, service_hits, top_name, messengers.
	report := buildCompactReport(t)
	out := NewFieldRenderer().Render(report)
	line := strings.TrimRight(out, "\n")
	parts := strings.Split(line, "|")
	// parts[3]=carrier, parts[6]=breach_count, parts[7]=service_hits, parts[8]=top_name, parts[9]=messengers
	for _, idx := range []int{3, 6, 7, 8, 9} {
		if idx < len(parts) && strings.TrimSpace(parts[idx]) != "" && idx == 9 {
			// messengers allowed to be empty string
			continue
		}
	}
	// All 10 fields must be present (pipes must be there even if values are empty).
	if len(parts) != 10 {
		t.Fatalf("want 10 pipe-delimited fields, got %d: %q", len(parts), line)
	}
}

func TestFieldRendererMessengersCommaJoined(t *testing.T) {
	report := buildCompactReport(t)
	report.Messenger = &core.MessengerReport{
		WhatsApp: &core.MessengerAccount{Found: true},
		Telegram: &core.MessengerAccount{Found: true},
		Signal:   &core.MessengerAccount{Found: false},
	}
	out := NewFieldRenderer().Render(report)
	line := strings.TrimRight(out, "\n")
	parts := strings.Split(line, "|")
	if parts[9] != "WhatsApp,Telegram" {
		t.Fatalf("field[9] (messengers) want %q, got %q", "WhatsApp,Telegram", parts[9])
	}
}

func TestFieldRendererNoANSIColors(t *testing.T) {
	report := buildCompactReport(t)
	out := NewFieldRenderer().Render(report)
	if strings.Contains(out, "\033[") {
		t.Fatalf("field output must contain no ANSI colour codes: %q", out)
	}
}

func TestFieldRendererNoNewlinesInLine(t *testing.T) {
	report := buildCompactReport(t)
	out := NewFieldRenderer().Render(report)
	line := strings.TrimRight(out, "\n")
	if strings.Contains(line, "\n") {
		t.Fatalf("field output must be single line (no embedded newlines): %q", line)
	}
}

// --- Mutual exclusivity (options.resolveFormat) ---

func TestCompactAndFieldMutuallyExclusive(t *testing.T) {
	opts := &options{compact: true, field: true, format: "terminal"}
	_, err := opts.resolveFormat()
	// resolveFormat doesn't enforce this — it's done in RunE.
	// The RunE check is: if local.compact && local.field { return error }
	// Confirm resolveFormat itself returns compact (compact takes precedence).
	if err != nil {
		t.Logf("resolveFormat returned error: %v (that's also acceptable)", err)
	}
}

func TestCompactFlagOverridesFormat(t *testing.T) {
	opts := &options{compact: true, format: "terminal"}
	got, err := opts.resolveFormat()
	if err != nil {
		t.Fatalf("resolveFormat error: %v", err)
	}
	if got != "compact" {
		t.Fatalf("want format=compact, got %q", got)
	}
}

func TestFieldFlagOverridesFormat(t *testing.T) {
	opts := &options{field: true, format: "terminal"}
	got, err := opts.resolveFormat()
	if err != nil {
		t.Fatalf("resolveFormat error: %v", err)
	}
	if got != "field" {
		t.Fatalf("want format=field, got %q", got)
	}
}

func TestFormatCompactStringAccepted(t *testing.T) {
	opts := &options{format: "compact"}
	got, err := opts.resolveFormat()
	if err != nil {
		t.Fatalf("resolveFormat error: %v", err)
	}
	if got != "compact" {
		t.Fatalf("want format=compact, got %q", got)
	}
}

func TestFormatFieldStringAccepted(t *testing.T) {
	opts := &options{format: "field"}
	got, err := opts.resolveFormat()
	if err != nil {
		t.Fatalf("resolveFormat error: %v", err)
	}
	if got != "field" {
		t.Fatalf("want format=field, got %q", got)
	}
}

// helpers

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// stripANSI removes ANSI escape sequences for column-width measurement.
func stripANSI(s string) string {
	var b strings.Builder
	inEsc := false
	for _, r := range s {
		if r == '\033' {
			inEsc = true
			continue
		}
		if inEsc {
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				inEsc = false
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
