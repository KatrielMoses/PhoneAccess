package publicrecords

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

type mockClient struct {
	t     *testing.T
	mu    sync.Mutex
	calls []string
	fn    func(*http.Request) (string, int)
}

func (m *mockClient) Do(req *http.Request) (*http.Response, error) {
	m.mu.Lock()
	m.calls = append(m.calls, req.URL.String())
	m.mu.Unlock()
	body, status := m.fn(req)
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}, nil
}

type memoryQuotaStore struct{}

func (memoryQuotaStore) ConsumeMonthlyQuota(string, int, time.Time) (bool, int, error) {
	return true, 1, nil
}

func mustNumber(t *testing.T, raw string) *core.PhoneNumber {
	t.Helper()
	number, err := core.NormalizePhoneNumber(raw)
	if err != nil {
		t.Fatalf("normalize %s: %v", raw, err)
	}
	return number
}

func TestRunExtractsEdgarHitsAndIdentityGraphPivots(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	number := mustNumber(t, "+14155552671")
	client := &mockClient{
		t: t,
		fn: func(req *http.Request) (string, int) {
			switch req.URL.Host {
			case "efts.sec.gov":
				return `{"hits":{"hits":[{"_source":{"entity_name":"Example Company Inc.","file_date":"2026-05-27","form_type":"8-K","period_of_report":"2026-05-26","filing_url":"https://www.sec.gov/Archives/edgar/data/0000123456/000012345626000001/0000123456-26-000001-index.htm"}}]}}`, http.StatusOK
			case "www.fsmb.org":
				return "", http.StatusOK
			case "apps.calbar.ca.gov", "www.trec.texas.gov":
				return "", http.StatusOK
			default:
				t.Fatalf("unexpected host: %s", req.URL.Host)
				return "", http.StatusInternalServerError
			}
		},
	}

	module := New(WithHTTPClient(client), WithQuotaStore(memoryQuotaStore{}), WithAPIKeys("", "", "", "", ""), WithNow(func() time.Time {
		return time.Date(2026, 5, 28, 0, 0, 0, 0, time.UTC)
	}))
	result, err := module.Run(context.Background(), number)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	data, ok := result.Data.(PublicRecordsResult)
	if !ok {
		t.Fatalf("result.Data type = %T, want PublicRecordsResult", result.Data)
	}
	if len(data.EdgarHits) != 1 {
		t.Fatalf("edgar hits = %#v, want 1 hit", data.EdgarHits)
	}
	if got := data.EdgarHits[0].EntityName; got != "Example Company Inc." {
		t.Fatalf("edgar entity = %q, want Example Company Inc.", got)
	}
	if got := data.SourceStatuses["SEC EDGAR"]; got != "hit" {
		t.Fatalf("source status = %q, want hit", got)
	}

	report := &core.InvestigationReport{
		Number:  number,
		Results: []*core.ModuleResult{result},
	}
	graph := core.BuildIdentityGraph(report)
	pivot := findPivot(graph, "name", "Example Company Inc.")
	if pivot == nil {
		t.Fatalf("expected entity name pivot in identity graph, got %#v", graph.PivotPoints)
	}
	if len(pivot.Modules) != 1 || pivot.Modules[0] != moduleName {
		t.Fatalf("pivot modules = %#v, want %q", pivot.Modules, moduleName)
	}
}

func TestPACERSkippedWithoutCredentials(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	number := mustNumber(t, "+14155552671")
	client := &mockClient{
		t: t,
		fn: func(req *http.Request) (string, int) {
			switch req.URL.Host {
			case "efts.sec.gov", "www.fsmb.org", "apps.calbar.ca.gov", "www.trec.texas.gov":
				return "", http.StatusOK
			default:
				t.Fatalf("unexpected network call to %s", req.URL.Host)
				return "", http.StatusInternalServerError
			}
		},
	}

	module := New(WithHTTPClient(client), WithQuotaStore(memoryQuotaStore{}), WithAPIKeys("", "", "", "", ""))
	if err := module.DryRun(context.Background(), number); err != nil {
		t.Fatalf("DryRun() error = %v, want nil", err)
	}
	result, err := module.Run(context.Background(), number)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	data := result.Data.(PublicRecordsResult)
	if got := data.SourceStatuses["PACER"]; got != "skipped" {
		t.Fatalf("PACER status = %q, want skipped", got)
	}
}

func TestLicenseDatabasesLoad(t *testing.T) {
	dbs := loadLicenseDatabases()
	if len(dbs) < 3 {
		t.Fatalf("loaded %d license databases, want at least 3", len(dbs))
	}
	want := map[string]bool{
		"FSMB Physician Data Center":                  false,
		"California State Bar Attorney Search":        false,
		"Texas Real Estate Commission License Search": false,
	}
	for _, db := range dbs {
		if _, ok := want[db.Name]; ok {
			want[db.Name] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("license database %q missing from YAML", name)
		}
	}
}

func TestPropertyHintsSkippedWithoutGoogleKey(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	number := mustNumber(t, "+14155552671")
	client := &mockClient{
		t: t,
		fn: func(req *http.Request) (string, int) {
			switch req.URL.Host {
			case "efts.sec.gov", "www.fsmb.org", "apps.calbar.ca.gov", "www.trec.texas.gov":
				return "", http.StatusOK
			case "api.company-information.service.gov.uk":
				return `{"items":[]}`, http.StatusOK
			default:
				t.Fatalf("unexpected network call to %s", req.URL.Host)
				return "", http.StatusInternalServerError
			}
		},
	}

	module := New(WithHTTPClient(client), WithQuotaStore(memoryQuotaStore{}), WithAPIKeys("", "", "", "", ""))
	result, err := module.Run(context.Background(), number)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	data := result.Data.(PublicRecordsResult)
	if got := data.SourceStatuses["Property hints"]; got != "skipped" {
		t.Fatalf("Property hints status = %q, want skipped", got)
	}
}

func TestNonUSNumberSkipsLicensesAndPropertyHints(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	number := mustNumber(t, "+447911123456")
	client := &mockClient{
		t: t,
		fn: func(req *http.Request) (string, int) {
			switch req.URL.Host {
			case "efts.sec.gov":
				return `{"hits":{"hits":[]}}`, http.StatusOK
			case "www.fsmb.org", "apps.calbar.ca.gov", "www.trec.texas.gov":
				return "", http.StatusOK
			default:
				t.Fatalf("unexpected network call to %s", req.URL.Host)
				return "", http.StatusInternalServerError
			}
		},
	}

	module := New(WithHTTPClient(client), WithQuotaStore(memoryQuotaStore{}), WithAPIKeys("", "", "", "", ""))
	result, err := module.Run(context.Background(), number)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	data := result.Data.(PublicRecordsResult)
	if got := data.SourceStatuses["Licenses"]; got != "skipped" {
		t.Fatalf("Licenses status = %q, want skipped", got)
	}
	if got := data.SourceStatuses["Property hints"]; got != "skipped" {
		t.Fatalf("Property hints status = %q, want skipped", got)
	}
}

func TestRunPassiveSkipsAllNetworkCalls(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	number := mustNumber(t, "+14155552671")
	client := &mockClient{
		t: t,
		fn: func(req *http.Request) (string, int) {
			t.Fatalf("unexpected network call to %s", req.URL.Host)
			return "", http.StatusInternalServerError
		},
	}

	module := New(WithHTTPClient(client), WithQuotaStore(memoryQuotaStore{}))
	result, err := module.RunPassive(context.Background(), number)
	if err != nil {
		t.Fatalf("RunPassive() error = %v", err)
	}
	if result.Status != core.ModuleStatusSkipped {
		t.Fatalf("status = %q, want skipped", result.Status)
	}
	data := result.Data.(PublicRecordsResult)
	if !data.Skipped {
		t.Fatalf("passive result should be marked skipped")
	}
}

func findPivot(graph *core.IdentityGraph, kind, value string) *core.IdentityPivot {
	for i := range graph.PivotPoints {
		pivot := &graph.PivotPoints[i]
		if pivot.Type == kind && pivot.Value == value {
			return pivot
		}
	}
	return nil
}
