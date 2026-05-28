package reverse

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
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

func TestNameFoundInOneSource(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	number := mustNumber(t)
	source := truecallerSource{}
	client := &mockClient{t: t, responses: map[string]string{
		source.URL(number): `<html><head><title>Jane Roe | Truecaller</title></head><body><div>Location: San Francisco, CA</div></body></html>`,
		waybackCDXURL(source.URL(number)): `[["timestamp","statuscode"]]`,
	}}

	result := runModule(t, number, client, source)
	data := result.Data.(ReverseResult)

	if data.NameHint != "Jane Roe" {
		t.Fatalf("name_hint = %q, want Jane Roe", data.NameHint)
	}
	if data.NameConfidence != "medium" {
		t.Fatalf("name_confidence = %q, want medium", data.NameConfidence)
	}
	if data.LocationHint != "San Francisco, CA" {
		t.Fatalf("location_hint = %q, want San Francisco, CA", data.LocationHint)
	}
}

func TestNameCorroboratedAcrossTwoSources(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	number := mustNumber(t)
	sources := []Source{truecallerSource{}, openCNAMSource{sid: "sid123"}}
	client := &mockClient{t: t, responses: responsesFor(number, sources, map[string]string{
		"Truecaller": `<html><body><script type="application/ld+json">{"name":"Jane Roe","addressLocality":"San Francisco"}</script></body></html>`,
		"OpenCNAM":   `{"name":"Jane Roe"}`,
	})}

	result := runModule(t, number, client, sources...)
	data := result.Data.(ReverseResult)

	if data.NameHint != "Jane Roe" {
		t.Fatalf("name_hint = %q, want Jane Roe", data.NameHint)
	}
	if data.NameConfidence != "high" {
		t.Fatalf("name_confidence = %q, want high", data.NameConfidence)
	}
	if len(data.SourcesWithHits) != 2 {
		t.Fatalf("sources_with_hits = %#v, want two hits", data.SourcesWithHits)
	}
}

func TestNoResults(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	number := mustNumber(t)
	sources := []Source{truecallerSource{}, googleDorkSource{}}
	client := &mockClient{t: t, responses: responsesFor(number, sources, map[string]string{
		"Truecaller": `<html><body>Log in to Truecaller to see this phone number profile.</body></html>`,
		"Google":     `<html><body>No results found.</body></html>`,
	})}

	result := runModule(t, number, client, sources...)
	data := result.Data.(ReverseResult)

	if data.NameHint != "" {
		t.Fatalf("name_hint = %q, want empty", data.NameHint)
	}
	if len(data.SourcesWithHits) != 0 {
		t.Fatalf("sources_with_hits = %#v, want empty", data.SourcesWithHits)
	}
	if result.Findings["sources_checked"] == "" {
		t.Fatal("sources_checked should be populated")
	}
}

func TestPivotEmailDiscoveredInSearchSnippet(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	number := mustNumber(t)
	source := googleDorkSource{}
	client := &mockClient{t: t, responses: map[string]string{
		source.URL(number): `<html><body>
			<h3>Owner: Jane Roe +14155552671</h3>
			<div class="VwiC3b">Contact Jane Roe at jane.roe@example.com or @janeroe for +1 415 555 2671.</div>
		</body></html>`,
		waybackCDXURL(source.URL(number)): `[["timestamp","statuscode"]]`,
	}}

	result := runModule(t, number, client, source)
	data := result.Data.(ReverseResult)

	if data.NameHint != "Jane Roe" || data.NameConfidence != "low" {
		t.Fatalf("name = %q confidence = %q, want Jane Roe low", data.NameHint, data.NameConfidence)
	}
	if !contains(data.PivotEmails, "jane.roe@example.com") {
		t.Fatalf("pivot_emails = %#v, want jane.roe@example.com", data.PivotEmails)
	}
	if !contains(data.PivotUsernames, "janeroe") {
		t.Fatalf("pivot_usernames = %#v, want janeroe", data.PivotUsernames)
	}
}

func TestWaybackFirstSeenCaptured(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	number := mustNumber(t)
	truecaller := truecallerSource{}
	google := googleDorkSource{}
	truecallerURL := truecaller.URL(number)
	googleURL := google.URL(number)
	client := &mockClient{t: t, responses: map[string]string{
		truecallerURL: `<!doctype html><html><body><div>Jane Roe</div></body></html>`,
		googleURL:     `<html><body><h3>Jane Roe</h3><div class="VwiC3b">Jane Roe jane.roe@example.com</div></body></html>`,
		waybackCDXURL(truecallerURL): `[["timestamp","statuscode"],["20240102030405","200"],["20240105000000","200"]]`,
		waybackCDXURL(googleURL):     `[["timestamp","statuscode"]]`,
	}}

	result := runModule(t, number, client, truecaller, google)
	data := result.Data.(ReverseResult)

	if len(data.WaybackHits) == 0 {
		t.Fatalf("wayback_hits = %#v, want at least one hit", data.WaybackHits)
	}
	if data.WaybackHits[0].FirstSeen != "20240102030405" {
		t.Fatalf("first_seen = %q, want 20240102030405", data.WaybackHits[0].FirstSeen)
	}
}

func TestZabaSearchSkippedForNonUS(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	number := &core.PhoneNumber{
		E164:           "+442071234567",
		CountryAlpha2:  "GB",
		NationalNumber: "2071234567",
	}
	module := New(
		WithHTTPClient(blockingClient{t: t}),
		WithRateLimiter(core.NewRateLimiter(0)),
		WithSources(zabaSearchSource{}),
	)

	result, err := module.Run(context.Background(), number)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	data := result.Data.(ReverseResult)

	if len(data.SourcesWithHits) != 0 {
		t.Fatalf("sources_with_hits = %#v, want none", data.SourcesWithHits)
	}
	if data.SourceStatuses["ZabaSearch"] != "no results" {
		t.Fatalf("zabasearch status = %q, want no results", data.SourceStatuses["ZabaSearch"])
	}
}

func TestPassiveSkip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	number := mustNumber(t)
	module := New(
		WithHTTPClient(blockingClient{t: t}),
		WithRateLimiter(core.NewRateLimiter(0)),
		WithOpenCNAMSID(""),
	)

	result, err := module.RunPassive(context.Background(), number)
	if err != nil {
		t.Fatalf("run passive: %v", err)
	}
	data := result.Data.(ReverseResult)

	if result.Status != core.ModuleStatusSkipped {
		t.Fatalf("status = %q, want skipped", result.Status)
	}
	if !data.Skipped || result.Findings["skipped"] != "true" {
		t.Fatalf("skipped data/findings = %#v / %#v, want true", data, result.Findings)
	}
}

func runModule(t *testing.T, number *core.PhoneNumber, client HTTPClient, sources ...Source) *core.ModuleResult {
	t.Helper()
	t.Setenv("HOME", t.TempDir())

	module := New(
		WithHTTPClient(client),
		WithRateLimiter(core.NewRateLimiter(0)),
		WithSources(sources...),
	)
	result, err := module.Run(context.Background(), number)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return result
}

func responsesFor(number *core.PhoneNumber, sources []Source, bySource map[string]string) map[string]string {
	out := map[string]string{}
	for _, source := range sources {
		sourceURL := source.URL(number)
		if sourceURL == "" {
			continue
		}
		out[sourceURL] = bySource[source.Name()]
		out[waybackCDXURL(sourceURL)] = `[["timestamp","statuscode"]]`
	}
	return out
}

func waybackCDXURL(target string) string {
	endpoint, _ := url.Parse("https://web.archive.org/cdx/search/cdx")
	query := endpoint.Query()
	query.Set("url", target)
	query.Set("output", "json")
	query.Set("fl", "timestamp,statuscode")
	query.Set("limit", "5")
	endpoint.RawQuery = query.Encode()
	return endpoint.String()
}

func mustNumber(t *testing.T) *core.PhoneNumber {
	t.Helper()

	number, err := core.NormalizePhoneNumber("+14155552671")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return number
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
