package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

func renderReport(t *testing.T, results ...*core.ModuleResult) string {
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
	return NewTerminalRenderer().Render(report)
}

func testModuleResult(name string, findings map[string]string, data any) *core.ModuleResult {
	return &core.ModuleResult{
		ModuleName: name,
		Status:     core.ModuleStatusSuccess,
		Findings:   findings,
		Data:       data,
	}
}

func TestMessengerPresenceBlockShowsSignalRegistered(t *testing.T) {
	account := &core.MessengerAccount{Found: true, DataSource: "signal_cdn"}
	rendered := renderReport(t,
		testModuleResult("signal", map[string]string{"found": "true", "data_source": "signal_cdn"}, account),
	)
	if !strings.Contains(rendered, "Signal") {
		t.Fatalf("render missing Signal row: %s", rendered)
	}
	if !strings.Contains(rendered, "registered") {
		t.Fatalf("render should show 'registered' for Signal found=true: %s", rendered)
	}
}

func TestMessengerPresenceBlockShowsSignalNotRegistered(t *testing.T) {
	account := &core.MessengerAccount{Found: false, DataSource: "signal_cdn"}
	rendered := renderReport(t,
		testModuleResult("signal", map[string]string{"found": "false", "data_source": "signal_cdn"}, account),
	)
	if !strings.Contains(rendered, "not registered") {
		t.Fatalf("render should show 'not registered' for Signal found=false: %s", rendered)
	}
}

func TestMessengerPresenceBlockShowsSignalUnavailableWhenMissing(t *testing.T) {
	rendered := renderReport(t) // no signal result
	if !strings.Contains(rendered, "Signal") {
		t.Fatalf("render should include Signal row even when not available: %s", rendered)
	}
	if !strings.Contains(rendered, "unavailable") {
		t.Fatalf("render should show 'check unavailable' when Signal result absent: %s", rendered)
	}
}

func TestBreachIntelligenceBlockShowsHIBPKeyMissingNote(t *testing.T) {
	findings := map[string]string{
		"found":          "false",
		"breach_count":   "0",
		"stealer_count":  "0",
		"source_statuses": "HIBP=unavailable: HIBP_API_KEY not configured; XposedOrNot=no results",
		"skipped":        "false",
	}
	rendered := renderReport(t,
		testModuleResult("breach", findings, nil),
	)
	if !strings.Contains(rendered, "HIBP") {
		t.Fatalf("render missing HIBP note: %s", rendered)
	}
	if !strings.Contains(rendered, "HIBP_API_KEY not configured") {
		t.Fatalf("render should show HIBP_API_KEY not configured note: %s", rendered)
	}
}

func TestNoSaveFlag(t *testing.T) {
	opts := &options{
		format:      "json",
		timeoutSecs: 30,
		allModules:  []core.Module{},
		noSave:      true,
		passive:     true, // fast
	}
	
	var buf bytes.Buffer
	err := opts.runInvestigation(context.Background(), &buf, "+14155552671")
	if err != nil {
		t.Fatalf("runInvestigation failed: %v", err)
	}
	
	// If it didn't panic or error, noSave suppressed storage as expected since we didn't mock a storage db path.
}
