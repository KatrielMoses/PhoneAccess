package spam

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

type mockClient struct {
	t         *testing.T
	responses map[string]string
	statuses  map[string]int
	err       error
	calls     []string
}

func (c *mockClient) Do(req *http.Request) (*http.Response, error) {
	c.calls = append(c.calls, req.URL.String())
	if c.err != nil {
		return nil, c.err
	}
	body, ok := c.responses[req.URL.String()]
	if !ok {
		c.t.Fatalf("unexpected request URL: %s", req.URL.String())
	}
	status := c.statuses[req.URL.String()]
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
	}, nil
}

type blockingClient struct {
	t *testing.T
}

func (c blockingClient) Do(req *http.Request) (*http.Response, error) {
	c.t.Fatalf("unexpected network call to %s", req.URL.String())
	return nil, errors.New("unexpected network call")
}

func TestHighSpamReports(t *testing.T) {
	number := mustNumber(t)
	responses := map[string]string{
		"https://800notes.com/Phone.aspx/415-555-2671": `
			<html><body>
				<h1>12 reports</h1>
				<div>Caller type: Scammer</div>
				<div>Most recent report: May 20, 2026</div>
				<div class="comment">Pretended to be from the bank and asked for a one-time code.</div>
				<div class="comment">Repeated calls saying my card was locked unless I paid immediately.</div>
			</body></html>`,
		"https://whocalledus.com/calls/4155552671/": `
			<html><body>
				<span>4 complaints</span>
				<p>Caller Type: Fraudster</p>
				<p class="message">Threatened account suspension and wanted gift cards over the phone.</p>
			</body></html>`,
		"https://www.spamcalls.net/en/search?number=14155552671": `
			<html><body>
				<strong>2 comments</strong>
				<div>Type: scam</div>
				<div>2026-05-21</div>
				<div class="report">Automated voice claimed there was legal action pending against me.</div>
			</body></html>`,
	}
	client := &mockClient{t: t, responses: responses}

	result := runModule(t, number, client)

	if result.Findings["total_reports"] != "18" {
		t.Fatalf("total_reports = %q, want 18", result.Findings["total_reports"])
	}
	if result.Findings["caller_type"] != "scammer" {
		t.Fatalf("caller_type = %q, want scammer", result.Findings["caller_type"])
	}
	if result.Findings["spam_score"] != "85" {
		t.Fatalf("spam_score = %q, want 85", result.Findings["spam_score"])
	}
	if result.Findings["safe"] != "false" {
		t.Fatalf("safe = %q, want false", result.Findings["safe"])
	}
	if result.Findings["most_recent_report"] != "2026-05-21" {
		t.Fatalf("most_recent_report = %q, want 2026-05-21", result.Findings["most_recent_report"])
	}
	if !strings.Contains(result.Findings["sources_with_hits"], "800notes") ||
		!strings.Contains(result.Findings["sources_with_hits"], "whocalledus") ||
		!strings.Contains(result.Findings["sources_with_hits"], "spamcalls") {
		t.Fatalf("sources_with_hits missing expected sources: %q", result.Findings["sources_with_hits"])
	}
	if got := len(strings.Split(result.Findings["report_snippets"], "\n")); got != 4 {
		t.Fatalf("snippet count = %d, want 4", got)
	}
}

func TestCleanNumberWithZeroReports(t *testing.T) {
	number := mustNumber(t)
	responses := map[string]string{
		"https://800notes.com/Phone.aspx/415-555-2671":           `<html><body>No reports found for this number.</body></html>`,
		"https://whocalledus.com/calls/4155552671/":              `<html><body>No complaints found.</body></html>`,
		"https://www.spamcalls.net/en/search?number=14155552671": `<html><body>No results for this phone number.</body></html>`,
	}
	client := &mockClient{t: t, responses: responses}

	result := runModule(t, number, client)

	if result.Findings["total_reports"] != "0" {
		t.Fatalf("total_reports = %q, want 0", result.Findings["total_reports"])
	}
	if result.Findings["safe"] != "true" {
		t.Fatalf("safe = %q, want true", result.Findings["safe"])
	}
	if result.Findings["spam_score"] != "0" {
		t.Fatalf("spam_score = %q, want 0", result.Findings["spam_score"])
	}
	if result.Findings["risk"] != "CLEAN" {
		t.Fatalf("risk = %q, want CLEAN", result.Findings["risk"])
	}
	if result.Findings["sources_with_hits"] != "" {
		t.Fatalf("sources_with_hits = %q, want empty", result.Findings["sources_with_hits"])
	}
}

func TestAllSourcesReturningErrors(t *testing.T) {
	number := mustNumber(t)
	client := &mockClient{t: t, err: errors.New("network down")}

	result := runModule(t, number, client)

	if result.Status != core.ModuleStatusSuccess {
		t.Fatalf("status = %q, want success", result.Status)
	}
	if result.Findings["total_reports"] != "0" {
		t.Fatalf("total_reports = %q, want 0", result.Findings["total_reports"])
	}
	if result.Findings["safe"] != "true" {
		t.Fatalf("safe = %q, want true", result.Findings["safe"])
	}
	for _, source := range []string{"800notes", "whocalledus", "spamcalls"} {
		if !strings.Contains(result.Findings["sources_checked"], source) {
			t.Fatalf("sources_checked missing %s: %q", source, result.Findings["sources_checked"])
		}
		if !strings.Contains(result.Findings["source_statuses"], source+"=unavailable") {
			t.Fatalf("source_statuses missing unavailable %s: %q", source, result.Findings["source_statuses"])
		}
	}
}

func TestPassiveModeSkip(t *testing.T) {
	number := mustNumber(t)
	module := New(
		WithHTTPClient(blockingClient{t: t}),
		WithRateLimiter(core.NewRateLimiter(0)),
	)

	result, err := module.RunPassive(context.Background(), number)
	if err != nil {
		t.Fatalf("run passive: %v", err)
	}
	if result.Status != core.ModuleStatusSkipped {
		t.Fatalf("status = %q, want skipped", result.Status)
	}
	if result.Findings["skipped"] != "true" {
		t.Fatalf("skipped = %q, want true", result.Findings["skipped"])
	}
	if !strings.Contains(result.Findings["note"], "passive mode") {
		t.Fatalf("note = %q, want passive mode explanation", result.Findings["note"])
	}
}

func runModule(t *testing.T, number *core.PhoneNumber, client HTTPClient) *core.ModuleResult {
	t.Helper()

	module := New(
		WithHTTPClient(client),
		WithRateLimiter(core.NewRateLimiter(0)),
	)
	result, err := module.Run(context.Background(), number)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return result
}

func mustNumber(t *testing.T) *core.PhoneNumber {
	t.Helper()

	number, err := core.NormalizePhoneNumber("+14155552671")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return number
}
