package breach

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

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

func TestNumberWithMultipleBreaches(t *testing.T) {
	number := mustNumber(t)
	responses := responsesFor(number, map[string]string{
		"XposedOrNot": `{
			"ExposedBreaches": {
				"breaches_details": [
					{"breach":"ExampleCom","xposed_date":"2022","xposed_data":"Phone numbers;Email addresses;Names"},
					{"breach":"ShopLeak","xposed_date":"2024-03-01","xposed_data":"Phone numbers;Physical addresses"}
				]
			}
		}`,
		"LeakCheck": `{
			"success": true,
			"found": 1,
			"result": [
				{"source":{"name":"MarketingDump","date":"2023-08-12","fields":["phone","email"]}}
			]
		}`,
		"HudsonRock Cavalier": `{"total":0,"stealers":[]}`,
	})
	client := &mockClient{t: t, responses: responses}

	result := runModule(t, number, client)
	data := result.Data.(BreachResult)

	if !data.Found {
		t.Fatalf("found = false, want true")
	}
	if data.BreachCount != 3 {
		t.Fatalf("breach_count = %d, want 3", data.BreachCount)
	}
	if data.MostRecentBreach != "2024-03-01" {
		t.Fatalf("most_recent_breach = %q, want 2024-03-01", data.MostRecentBreach)
	}
	if !contains(data.DataClassesSeen, "Phone numbers") || !contains(data.DataClassesSeen, "email") {
		t.Fatalf("data_classes_seen missing expected values: %#v", data.DataClassesSeen)
	}
	if result.Findings["found"] != "true" || result.Findings["breach_count"] != "3" {
		t.Fatalf("unexpected findings: %#v", result.Findings)
	}
	// 3 original sources + Scylla.sh (no key required); keyed sources skipped when key absent.
	if len(client.calls) != 4 {
		t.Fatalf("calls = %d, want 4", len(client.calls))
	}
}

func TestCleanNumber(t *testing.T) {
	number := mustNumber(t)
	responses := responsesFor(number, map[string]string{
		"XposedOrNot":         `{"Error":"Not found"}`,
		"LeakCheck":           `{"success":true,"found":0,"result":[]}`,
		"HudsonRock Cavalier": `{"found":false,"stealers":[]}`,
	})
	client := &mockClient{t: t, responses: responses}

	result := runModule(t, number, client)
	data := result.Data.(BreachResult)

	if data.Found {
		t.Fatalf("found = true, want false")
	}
	if data.BreachCount != 0 || data.StealerCount != 0 {
		t.Fatalf("counts = breaches %d stealers %d, want zero", data.BreachCount, data.StealerCount)
	}
	if result.Findings["found"] != "false" {
		t.Fatalf("finding found = %q, want false", result.Findings["found"])
	}
}

func TestStealerLogHit(t *testing.T) {
	number := mustNumber(t)
	responses := responsesFor(number, map[string]string{
		"XposedOrNot": `{"Error":"Not found"}`,
		"LeakCheck":   `{"success":true,"found":0,"result":[]}`,
		"HudsonRock Cavalier": `{
			"stealers": [
				{"computer_name":"DESKTOP-1","credentials":[{"url":"https://example.com"}]},
				{"computer_name":"LAPTOP-2","credentials":[]}
			],
			"credentials_found": true
		}`,
	})
	client := &mockClient{t: t, responses: responses}

	result := runModule(t, number, client)
	data := result.Data.(BreachResult)

	if !data.Found {
		t.Fatalf("found = false, want true")
	}
	if data.StealerCount != 2 {
		t.Fatalf("stealer_count = %d, want 2", data.StealerCount)
	}
	if data.CompromisedMachineCount != 2 {
		t.Fatalf("compromised_machine_count = %d, want 2", data.CompromisedMachineCount)
	}
	if !data.CredentialsFound {
		t.Fatalf("credentials_found = false, want true")
	}
	if data.SourceStatuses["HudsonRock Cavalier"] != "hit" {
		t.Fatalf("HudsonRock status = %q, want hit", data.SourceStatuses["HudsonRock Cavalier"])
	}
}

func TestAllSourcesDown(t *testing.T) {
	number := mustNumber(t)
	client := &mockClient{t: t, err: errors.New("network down")}

	result := runModule(t, number, client)
	data := result.Data.(BreachResult)

	if result.Status != core.ModuleStatusSuccess {
		t.Fatalf("status = %q, want success", result.Status)
	}
	if data.Found {
		t.Fatalf("found = true, want false")
	}
	for _, source := range []string{"XposedOrNot", "LeakCheck", "HudsonRock Cavalier"} {
		if !strings.Contains(data.SourceStatuses[source], "unavailable") {
			t.Fatalf("source %s status = %q, want unavailable", source, data.SourceStatuses[source])
		}
	}
}

func TestPassiveSkip(t *testing.T) {
	number := mustNumber(t)
	module := New(
		WithHTTPClient(blockingClient{t: t}),
		WithRateLimiter(core.NewRateLimiter(0)),
	)

	result, err := module.RunPassive(context.Background(), number)
	if err != nil {
		t.Fatalf("run passive: %v", err)
	}
	data := result.Data.(BreachResult)

	if result.Status != core.ModuleStatusSkipped {
		t.Fatalf("status = %q, want skipped", result.Status)
	}
	if !data.Skipped || result.Findings["skipped"] != "true" {
		t.Fatalf("skipped data/findings = %#v / %#v, want true", data, result.Findings)
	}
	for _, source := range []string{"XposedOrNot", "LeakCheck", "HudsonRock Cavalier"} {
		if data.SourceStatuses[source] != "skipped" {
			t.Fatalf("source %s status = %q, want skipped", source, data.SourceStatuses[source])
		}
	}
}

func TestJSONIncludesStructuredBreachKey(t *testing.T) {
	number := mustNumber(t)
	result := BreachResult{
		Found:          true,
		BreachCount:    1,
		SourcesChecked: []string{"XposedOrNot"},
		Breaches: []BreachEntry{{
			Name:        "ExampleCom",
			Date:        "2022-01-01",
			DataClasses: []string{"Phone numbers"},
			SourceAPI:   "XposedOrNot",
		}},
		SourceStatuses: map[string]string{"XposedOrNot": "hit"},
	}
	report := &core.InvestigationReport{
		GeneratedAt: time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC),
		Number:      number,
		Results: []*core.ModuleResult{{
			ModuleName: "breach",
			Status:     core.ModuleStatusSuccess,
			Findings:   findingsFromBreachResult(result),
			Data:       result,
		}},
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	breachValue, ok := decoded["breach"].(map[string]any)
	if !ok {
		t.Fatalf("breach key missing or wrong type in %s", encoded)
	}
	if breachValue["breach_count"].(float64) != 1 {
		t.Fatalf("breach_count = %v, want 1", breachValue["breach_count"])
	}
}

// --- New source tests ---

func TestSnusbaseKeyAbsentSkipsCleanly(t *testing.T) {
	t.Setenv("SNUSBASE_API_KEY", "")
	number := mustNumber(t)

	// Module configured with only Snusbase; blockingClient panics if HTTP is called.
	// Since the key is absent, PrepareRequest returns an error and no HTTP call is made.
	module := New(
		WithHTTPClient(blockingClient{t: t}),
		WithRateLimiter(core.NewRateLimiter(0)),
		WithSources(snusbaseSource{}),
	)
	result, err := module.Run(context.Background(), number)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	data := result.Data.(BreachResult)
	if !strings.Contains(data.SourceStatuses["Snusbase"], "unavailable") {
		t.Fatalf("Snusbase status = %q, want unavailable", data.SourceStatuses["Snusbase"])
	}
}

func TestScyllaNoKeyAlwaysRuns(t *testing.T) {
	number := mustNumber(t)
	scyllaURL := scyllaSource{}.URL(number)
	responses := map[string]string{
		scyllaURL: `[{"_source":{"email":"x@y.com","username":"alice","breach":"ScyllaBreach"}}]`,
	}
	module := New(
		WithHTTPClient(&mockClient{t: t, responses: responses}),
		WithRateLimiter(core.NewRateLimiter(0)),
		WithSources(scyllaSource{}),
	)
	result, err := module.Run(context.Background(), number)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	data := result.Data.(BreachResult)
	if !data.Found {
		t.Fatalf("found = false, want true")
	}
	if data.BreachCount != 1 {
		t.Fatalf("breach_count = %d, want 1", data.BreachCount)
	}
	if data.Breaches[0].Name != "ScyllaBreach" {
		t.Fatalf("breach name = %q, want ScyllaBreach", data.Breaches[0].Name)
	}
	if len(data.Breaches[0].Emails) == 0 || data.Breaches[0].Emails[0] != "x@y.com" {
		t.Fatalf("email not extracted: %v", data.Breaches[0].Emails)
	}
	if len(data.Breaches[0].Usernames) == 0 || data.Breaches[0].Usernames[0] != "alice" {
		t.Fatalf("username not extracted: %v", data.Breaches[0].Usernames)
	}
}

func TestAllFourNewSourcesMergeIntoBreachResult(t *testing.T) {
	t.Setenv("SNUSBASE_API_KEY", "test-key")
	t.Setenv("BREACHDIRECTORY_API_KEY", "test-key")
	t.Setenv("LEAKLOOKUP_API_KEY", "test-key")

	number := mustNumber(t)

	snusbaseURL := snusbaseSource{}.URL(number)
	bdURL := breachDirectorySource{}.URL(number)
	llURL := leakLookupSource{}.URL(number)
	scyllaURL := scyllaSource{}.URL(number)

	responses := map[string]string{
		snusbaseURL: `{"results":{"phone":{"DB1":[{"email":"a@b.com","username":"user1","database":"SnusDB","created":"2023"}]}}}`,
		bdURL:       `{"success":true,"found":1,"result":[{"sources":["BDSource"],"passwords":["abc123"]}]}`,
		llURL:       `{"error":"false","message":{"LLSource":"1"}}`,
		scyllaURL:   `[{"_source":{"email":"c@d.com","username":"user2","breach":"ScyllaDB"}}]`,
	}

	module := New(
		WithHTTPClient(&mockClient{t: t, responses: responses}),
		WithRateLimiter(core.NewRateLimiter(0)),
		WithSources(snusbaseSource{}, breachDirectorySource{}, leakLookupSource{}, scyllaSource{}),
	)

	result, err := module.Run(context.Background(), number)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	data := result.Data.(BreachResult)

	if !data.Found {
		t.Fatalf("found = false, want true")
	}

	// Snusbase hit
	if data.SourceStatuses["Snusbase"] != "hit" {
		t.Fatalf("Snusbase status = %q, want hit", data.SourceStatuses["Snusbase"])
	}
	// BreachDirectory hit (credentials_found = true due to passwords)
	if !data.CredentialsFound {
		t.Fatalf("credentials_found = false, want true (BreachDirectory returned passwords)")
	}
	// Leak-Lookup hit
	if data.SourceStatuses["Leak-Lookup"] != "hit" {
		t.Fatalf("Leak-Lookup status = %q, want hit", data.SourceStatuses["Leak-Lookup"])
	}
	// Scylla hit
	if data.SourceStatuses["Scylla.sh"] != "hit" {
		t.Fatalf("Scylla.sh status = %q, want hit", data.SourceStatuses["Scylla.sh"])
	}

	// Emails and usernames from Snusbase and Scylla are merged into breaches
	var allEmails, allUsernames []string
	for _, b := range data.Breaches {
		allEmails = append(allEmails, b.Emails...)
		allUsernames = append(allUsernames, b.Usernames...)
	}
	if !contains(allEmails, "a@b.com") {
		t.Fatalf("a@b.com not in emails: %v", allEmails)
	}
	if !contains(allEmails, "c@d.com") {
		t.Fatalf("c@d.com not in emails: %v", allEmails)
	}
	if !contains(allUsernames, "user1") {
		t.Fatalf("user1 not in usernames: %v", allUsernames)
	}
	if !contains(allUsernames, "user2") {
		t.Fatalf("user2 not in usernames: %v", allUsernames)
	}
}

func TestBreachDirectoryCredentialsFlag(t *testing.T) {
	t.Setenv("BREACHDIRECTORY_API_KEY", "test-key")
	number := mustNumber(t)
	bdURL := breachDirectorySource{}.URL(number)
	responses := map[string]string{
		bdURL: `{"success":true,"found":2,"result":[{"sources":["Source1","Source2"],"passwords":["hash1"]}]}`,
	}
	module := New(
		WithHTTPClient(&mockClient{t: t, responses: responses}),
		WithRateLimiter(core.NewRateLimiter(0)),
		WithSources(breachDirectorySource{}),
	)
	result, err := module.Run(context.Background(), number)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	data := result.Data.(BreachResult)
	if !data.CredentialsFound {
		t.Fatalf("credentials_found = false, want true")
	}
	if data.BreachCount != 2 {
		t.Fatalf("breach_count = %d, want 2", data.BreachCount)
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

func responsesFor(number *core.PhoneNumber, bySource map[string]string) map[string]string {
	sources := []Source{xposedOrNotSource{}, leakCheckSource{}, hudsonRockSource{}}
	out := map[string]string{}
	for _, source := range sources {
		out[source.URL(number)] = bySource[source.Name()]
	}
	// Scylla.sh requires no key and is always called; add a safe default.
	scyllaResp := bySource["Scylla.sh"]
	if scyllaResp == "" {
		scyllaResp = "[]"
	}
	out[scyllaSource{}.URL(number)] = scyllaResp
	return out
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
