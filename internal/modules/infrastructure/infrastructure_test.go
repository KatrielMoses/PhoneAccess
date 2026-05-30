package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

type mockHTTPClient struct {
	handlers []mockHandler
}

type mockHandler struct {
	match   string // substring of URL (or "POST:" prefix for POST body match)
	status  int
	body    string
	latency time.Duration
}

func (c *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	key := req.URL.String()
	if req.Method == http.MethodPost {
		key = "POST:" + req.URL.String()
	}
	for _, h := range c.handlers {
		if strings.Contains(key, h.match) {
			if h.latency > 0 {
				time.Sleep(h.latency)
			}
			return &http.Response{
				StatusCode: h.status,
				Body:       io.NopCloser(bytes.NewBufferString(h.body)),
			}, nil
		}
	}
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(strings.NewReader("")),
	}, nil
}

func testNumber() *core.PhoneNumber {
	return &core.PhoneNumber{
		E164:           "+14155552671",
		NationalNumber: "4155552671",
		SearchVariants: []string{"+14155552671", "14155552671", "4155552671"},
		Valid:          true,
	}
}

func zeroDelayOpts() []Option {
	return []Option{
		WithCRTDelay(0),
		WithRDAPDelay(0),
		WithVTDelay(0),
		WithMBDelay(0),
	}
}

// ---------------------------------------------------------------------------
// crt.sh tests
// ---------------------------------------------------------------------------

func TestCRTReturnsDomainsAndAddedToFindings(t *testing.T) {
	crtPayload, _ := json.Marshal([]crtEntry{
		{
			CommonName:  "example.com",
			NameValue:   "example.com\nwww.example.com",
			IssuerName:  "O=Let's Encrypt, C=US",
			NotBefore:   "2024-03-15T00:00:00",
			NotAfter:    "2024-06-15T00:00:00",
			EntryTimestamp: "2024-03-15T00:00:01",
		},
	})

	client := &mockHTTPClient{handlers: []mockHandler{
		{match: "crt.sh", status: 200, body: string(crtPayload)},
		{match: "iana.org/rdap", status: 200, body: `{"services":[]}`},
		{match: "mb-api.abuse.ch", status: 200, body: `{"query_status":"no_results","data":[]}`},
	}}

	opts := append(zeroDelayOpts(), WithHTTPClient(client))
	m := New(opts...)

	result, err := m.Run(context.Background(), testNumber())
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	ir, ok := result.Data.(InfrastructureResult)
	if !ok {
		t.Fatal("Data is not InfrastructureResult")
	}

	if len(ir.CertHits) == 0 {
		t.Fatal("expected cert hits, got none")
	}

	domains := result.Findings["discovered_domains"]
	if !strings.Contains(domains, "example.com") {
		t.Errorf("discovered_domains = %q, want example.com", domains)
	}

	if result.Findings["cert_domain_count"] == "0" {
		t.Error("cert_domain_count should be > 0")
	}
}

func TestCRTEmptyResponseReturnsCleanResult(t *testing.T) {
	client := &mockHTTPClient{handlers: []mockHandler{
		{match: "crt.sh", status: 200, body: `[]`},
		{match: "iana.org/rdap", status: 200, body: `{"services":[]}`},
		{match: "mb-api.abuse.ch", status: 200, body: `{"query_status":"no_results","data":[]}`},
	}}

	opts := append(zeroDelayOpts(), WithHTTPClient(client))
	m := New(opts...)

	result, err := m.Run(context.Background(), testNumber())
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	if result.Findings["cert_domain_count"] != "0" {
		t.Errorf("cert_domain_count = %q, want 0", result.Findings["cert_domain_count"])
	}
	ir := result.Data.(InfrastructureResult)
	if len(ir.CertHits) != 0 {
		t.Errorf("CertHits = %d, want 0", len(ir.CertHits))
	}
}

// ---------------------------------------------------------------------------
// RDAP bootstrap caching test
// ---------------------------------------------------------------------------

func TestRDAPBootstrapCachedForRunDuration(t *testing.T) {
	var bootstrapCalls int32

	bootstrapBody := `{"services":[[["com"],["https://rdap.example.test/com/v1"]]]}`
	// crt.sh returns a domain so RDAP/WHOIS is actually exercised (and bootstrap loaded).
	client := &mockHTTPClient{handlers: []mockHandler{
		{match: "crt.sh", status: 200, body: crtPayloadForDomain("example.com")},
		{match: "iana.org/rdap", status: 200, body: bootstrapBody},
		{match: "rdap.example.test", status: 404, body: ``},
		{match: "mb-api.abuse.ch", status: 200, body: `{"query_status":"no_results","data":[]}`},
	}}

	// Wrap the client to count bootstrap calls.
	counting := &countingClient{
		inner:   client,
		pattern: "iana.org/rdap",
		counter: &bootstrapCalls,
	}

	opts := append(zeroDelayOpts(), WithHTTPClient(counting))
	m := New(opts...)

	// Call Run twice; bootstrap should only be fetched once.
	for i := 0; i < 2; i++ {
		if _, err := m.Run(context.Background(), testNumber()); err != nil {
			t.Fatalf("Run %d error: %v", i, err)
		}
	}

	if atomic.LoadInt32(&bootstrapCalls) != 1 {
		t.Errorf("bootstrap fetched %d times, want 1", atomic.LoadInt32(&bootstrapCalls))
	}
}

type countingClient struct {
	inner   HTTPClient
	pattern string
	counter *int32
}

func (c *countingClient) Do(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.String(), c.pattern) {
		atomic.AddInt32(c.counter, 1)
	}
	return c.inner.Do(req)
}

// ---------------------------------------------------------------------------
// WHOIS registrant extraction test
// ---------------------------------------------------------------------------

func TestWHOISRegistrantExtractedAndAddedToFindings(t *testing.T) {
	rdapDomainBody := `{
		"ldhName": "example.com",
		"events": [
			{"eventAction": "registration", "eventDate": "2019-04-10T00:00:00Z"},
			{"eventAction": "expiration",   "eventDate": "2026-04-10T00:00:00Z"}
		],
		"entities": [{
			"roles": ["registrant"],
			"vcardArray": ["vcard", [
				["version", {}, "text", "4.0"],
				["fn",      {}, "text", "John Smith"],
				["org",     {}, "text", "Acme Corp"],
				["email",   {}, "text", "john@example.com"]
			]]
		}]
	}`

	bootstrapBody := `{"services":[[["com"],["https://rdap.example.test/com/v1"]]]}`

	client := &mockHTTPClient{handlers: []mockHandler{
		{match: "crt.sh", status: 200, body: crtPayloadForDomain("example.com")},
		{match: "iana.org/rdap", status: 200, body: bootstrapBody},
		{match: "rdap.example.test", status: 200, body: rdapDomainBody},
		{match: "mb-api.abuse.ch", status: 200, body: `{"query_status":"no_results","data":[]}`},
	}}

	opts := append(zeroDelayOpts(), WithHTTPClient(client))
	m := New(opts...)

	result, err := m.Run(context.Background(), testNumber())
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	ir := result.Data.(InfrastructureResult)
	if len(ir.WhoisHits) == 0 {
		t.Fatal("expected WHOIS hits, got none")
	}

	hit := ir.WhoisHits[0]
	if hit.RegistrantName != "John Smith" {
		t.Errorf("RegistrantName = %q, want John Smith", hit.RegistrantName)
	}
	if hit.RegistrantEmail != "john@example.com" {
		t.Errorf("RegistrantEmail = %q, want john@example.com", hit.RegistrantEmail)
	}
	if hit.RegistrationDate != "2019-04-10" {
		t.Errorf("RegistrationDate = %q, want 2019-04-10", hit.RegistrationDate)
	}

	// Names and emails must appear in findings for the identity graph.
	if !strings.Contains(result.Findings["registrant_names"], "John Smith") {
		t.Errorf("registrant_names = %q, want John Smith", result.Findings["registrant_names"])
	}
	if !strings.Contains(result.Findings["registrant_emails"], "john@example.com") {
		t.Errorf("registrant_emails = %q, want john@example.com", result.Findings["registrant_emails"])
	}
}

// ---------------------------------------------------------------------------
// VirusTotal tests
// ---------------------------------------------------------------------------

func TestVTKeyAbsentSkipsVT(t *testing.T) {
	var vtCalled bool
	client := &mockHTTPClient{handlers: []mockHandler{
		{match: "crt.sh", status: 200, body: `[]`},
		{match: "iana.org/rdap", status: 200, body: `{"services":[]}`},
		{match: "mb-api.abuse.ch", status: 200, body: `{"query_status":"no_results","data":[]}`},
		{match: "virustotal.com", status: 200, body: `{}`, latency: 0},
	}}
	// Override to detect if VT was called.
	detecting := &detectingClient{inner: client, pattern: "virustotal.com", called: &vtCalled}

	opts := append(zeroDelayOpts(), WithHTTPClient(detecting))
	m := New(opts...)
	// No VIRUSTOTAL_API_KEY set in env, so key is empty.

	result, err := m.Run(context.Background(), testNumber())
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	if vtCalled {
		t.Error("VT was called without an API key")
	}

	ir := result.Data.(InfrastructureResult)
	if len(ir.VirusTotalHits) != 0 {
		t.Errorf("VirusTotalHits = %d, want 0", len(ir.VirusTotalHits))
	}
	if result.Findings["vt_configured"] != "false" {
		t.Errorf("vt_configured = %q, want false", result.Findings["vt_configured"])
	}
}

type detectingClient struct {
	inner   HTTPClient
	pattern string
	called  *bool
}

func (c *detectingClient) Do(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.String(), c.pattern) {
		*c.called = true
	}
	return c.inner.Do(req)
}

func TestVTHitAddsToFindings(t *testing.T) {
	vtBody := `{"data":[{
		"type": "file", "id": "abc123",
		"attributes": {
			"last_analysis_results": {
				"Kaspersky": {"category": "malicious", "result": "Trojan.SMS"}
			},
			"tags": ["smishing"],
			"domains": [],
			"ip_addresses": []
		}
	}]}`

	client := &mockHTTPClient{handlers: []mockHandler{
		{match: "crt.sh", status: 200, body: `[]`},
		{match: "iana.org/rdap", status: 200, body: `{"services":[]}`},
		{match: "mb-api.abuse.ch", status: 200, body: `{"query_status":"no_results","data":[]}`},
		{match: "virustotal.com", status: 200, body: vtBody},
	}}

	opts := append(zeroDelayOpts(), WithHTTPClient(client))
	m := New(opts...)

	ctx := context.WithValue(context.Background(), struct{ key string }{"VIRUSTOTAL_API_KEY"}, "testkey")
	// Use t.Setenv to inject the key.
	t.Setenv("VIRUSTOTAL_API_KEY", "testkey")

	result, err := m.Run(ctx, testNumber())
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	ir := result.Data.(InfrastructureResult)
	if len(ir.VirusTotalHits) == 0 {
		t.Fatal("expected VT hits, got none")
	}

	if ir.VirusTotalHits[0].HitCount != 1 {
		t.Errorf("VT HitCount = %d, want 1", ir.VirusTotalHits[0].HitCount)
	}

	vtHitCount := result.Findings["vt_hit_count"]
	if vtHitCount == "0" || vtHitCount == "" {
		t.Errorf("vt_hit_count = %q, want > 0", vtHitCount)
	}
	if !strings.Contains(result.Findings["vt_threat_labels"], "smishing") &&
		!strings.Contains(result.Findings["vt_threat_labels"], "Kaspersky") {
		t.Errorf("vt_threat_labels = %q, expected threat label present", result.Findings["vt_threat_labels"])
	}
}

func TestVTRateLimitExactDelay(t *testing.T) {
	var requestTimes []time.Time
	client := &mockHTTPClient{handlers: []mockHandler{
		{match: "crt.sh", status: 200, body: `[]`},
		{match: "iana.org/rdap", status: 200, body: `{"services":[]}`},
		{match: "mb-api.abuse.ch", status: 200, body: `{"query_status":"no_results","data":[]}`},
		{match: "virustotal.com", status: 200, body: `{"data":[]}`},
	}}
	recording := &recordingClient{inner: client, pattern: "virustotal.com", times: &requestTimes}

	const vtDelay = 50 * time.Millisecond
	opts := []Option{
		WithHTTPClient(recording),
		WithCRTDelay(0),
		WithRDAPDelay(0),
		WithMBDelay(0),
		WithVTDelay(vtDelay),
	}
	t.Setenv("VIRUSTOTAL_API_KEY", "testkey")

	m := New(opts...)

	// Run twice to exercise the rate limiter.
	for i := 0; i < 2; i++ {
		if _, err := m.Run(context.Background(), testNumber()); err != nil {
			t.Fatalf("Run %d error: %v", i, err)
		}
	}

	if len(requestTimes) < 2 {
		t.Fatalf("expected 2 VT requests, got %d", len(requestTimes))
	}
	gap := requestTimes[1].Sub(requestTimes[0])
	if gap < vtDelay {
		t.Errorf("VT inter-request gap = %v, want >= %v (no-jitter rate limit)", gap, vtDelay)
	}
}

type recordingClient struct {
	inner   HTTPClient
	pattern string
	times   *[]time.Time
}

func (c *recordingClient) Do(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.String(), c.pattern) {
		*c.times = append(*c.times, time.Now())
	}
	return c.inner.Do(req)
}

// ---------------------------------------------------------------------------
// MalwareBazaar tests
// ---------------------------------------------------------------------------

func TestMalwareBazaarHitAddedToFindings(t *testing.T) {
	mbBody := `{"query_status":"ok","data":[{
		"sha256_hash": "aabbcc",
		"file_type":   "exe",
		"signature":   "SMSRat",
		"tags":        ["smishing","rat"]
	}]}`

	client := &mockHTTPClient{handlers: []mockHandler{
		{match: "crt.sh", status: 200, body: `[]`},
		{match: "iana.org/rdap", status: 200, body: `{"services":[]}`},
		{match: "mb-api.abuse.ch", status: 200, body: mbBody},
	}}

	opts := append(zeroDelayOpts(), WithHTTPClient(client))
	m := New(opts...)

	result, err := m.Run(context.Background(), testNumber())
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	ir := result.Data.(InfrastructureResult)
	if len(ir.MalwareHits) == 0 {
		t.Fatal("expected malware hits, got none")
	}
	if ir.MalwareHits[0].SHA256 != "aabbcc" {
		t.Errorf("SHA256 = %q, want aabbcc", ir.MalwareHits[0].SHA256)
	}

	if result.Findings["malware_sample_count"] != "1" {
		t.Errorf("malware_sample_count = %q, want 1", result.Findings["malware_sample_count"])
	}
	if !strings.Contains(result.Findings["malware_families"], "SMSRat") {
		t.Errorf("malware_families = %q, want SMSRat", result.Findings["malware_families"])
	}
}

func TestMalwareBazaarNoHitReturnsClean(t *testing.T) {
	client := &mockHTTPClient{handlers: []mockHandler{
		{match: "crt.sh", status: 200, body: `[]`},
		{match: "iana.org/rdap", status: 200, body: `{"services":[]}`},
		{match: "mb-api.abuse.ch", status: 200, body: `{"query_status":"no_results","data":[]}`},
	}}

	opts := append(zeroDelayOpts(), WithHTTPClient(client))
	m := New(opts...)

	result, err := m.Run(context.Background(), testNumber())
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	if result.Findings["malware_sample_count"] != "0" {
		t.Errorf("malware_sample_count = %q, want 0", result.Findings["malware_sample_count"])
	}
}

// ---------------------------------------------------------------------------
// Module tier test
// ---------------------------------------------------------------------------

func TestInfrastructureModuleIsTierActive(t *testing.T) {
	m := New()
	if m.Tier() != core.TierActive {
		t.Errorf("Tier() = %v, want TierActive", m.Tier())
	}
}

// ---------------------------------------------------------------------------
// Concurrency test — all four goroutines run concurrently
// ---------------------------------------------------------------------------

func TestAllFourSourcesRunConcurrently(t *testing.T) {
	// Each HTTP round-trip sleeps 50ms. With true concurrency the critical path is:
	//   crt.sh (1 request = 50ms) → WHOIS bootstrap (50ms) + RDAP domain (50ms)
	// while MB and VT run in parallel with crt.sh.
	// Total: ~150ms. Sequential would be 5×50ms = 250ms.
	const sourceDelay = 50 * time.Millisecond

	// Use a number with no SearchVariants so crt.sh makes exactly one request.
	singleVariantNumber := &core.PhoneNumber{
		E164:  "+14155552671",
		Valid: true,
	}

	client := &mockHTTPClient{handlers: []mockHandler{
		{match: "crt.sh", status: 200, body: crtPayloadForDomain("example.com"), latency: sourceDelay},
		{match: "iana.org/rdap", status: 200, body: `{"services":[[["com"],["https://rdap.test/v1"]]]}`, latency: sourceDelay},
		{match: "rdap.test", status: 200, body: `{"ldhName":"example.com","entities":[]}`, latency: sourceDelay},
		{match: "mb-api.abuse.ch", status: 200, body: `{"query_status":"no_results","data":[]}`, latency: sourceDelay},
		{match: "virustotal.com", status: 200, body: `{"data":[]}`, latency: sourceDelay},
	}}

	t.Setenv("VIRUSTOTAL_API_KEY", "testkey")
	opts := []Option{
		WithHTTPClient(client),
		WithCRTDelay(0),
		WithRDAPDelay(0),
		WithMBDelay(0),
		WithVTDelay(0),
	}
	m := New(opts...)

	start := time.Now()
	if _, err := m.Run(context.Background(), singleVariantNumber); err != nil {
		t.Fatalf("Run error: %v", err)
	}
	elapsed := time.Since(start)

	// Critical path: crt.sh (50ms) + bootstrap (50ms) + rdap (50ms) = 150ms.
	// Sequential worst case: 5×50ms = 250ms.
	// Allow generous padding; the key assertion is we're well under sequential.
	maxExpected := 3*sourceDelay + 30*time.Millisecond
	if elapsed > maxExpected {
		t.Errorf("elapsed = %v, want < %v — MB and VT should run concurrently with crt.sh", elapsed, maxExpected)
	}
}

// ---------------------------------------------------------------------------
// Risk score integration — VT adds +15, MalwareBazaar adds +20
// ---------------------------------------------------------------------------

func TestVTHitAddsToRiskScore(t *testing.T) {
	report := &core.InvestigationReport{
		Results: []*core.ModuleResult{
			{
				ModuleName: "infrastructure",
				Status:     core.ModuleStatusSuccess,
				Findings: map[string]string{
					"vt_hit_count":         "1",
					"vt_threat_labels":     "smishing",
					"malware_sample_count": "0",
					"vt_configured":        "true",
				},
			},
		},
	}

	score := core.ScoreRisk(report)
	found := false
	for _, d := range score.Drivers {
		if d.Label == "VirusTotal threat association" && d.Points == 15 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected driver 'VirusTotal threat association' with 15 pts; drivers = %+v", score.Drivers)
	}
}

func TestMalwareBazaarHitAddsToRiskScore(t *testing.T) {
	report := &core.InvestigationReport{
		Results: []*core.ModuleResult{
			{
				ModuleName: "infrastructure",
				Status:     core.ModuleStatusSuccess,
				Findings: map[string]string{
					"vt_hit_count":         "0",
					"malware_sample_count": "1",
					"malware_families":     "SMSRat",
					"vt_configured":        "true",
				},
			},
		},
	}

	score := core.ScoreRisk(report)
	found := false
	for _, d := range score.Drivers {
		if d.Label == "Number found in malware sample" && d.Points == 20 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected driver 'Number found in malware sample' with 20 pts; drivers = %+v", score.Drivers)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func crtPayloadForDomain(domain string) string {
	entries := []crtEntry{{
		CommonName:     domain,
		NameValue:      domain,
		IssuerName:     "O=Let's Encrypt, C=US",
		NotBefore:      "2024-01-01T00:00:00",
		NotAfter:       "2024-04-01T00:00:00",
		EntryTimestamp: "2024-01-01T00:00:01",
	}}
	b, _ := json.Marshal(entries)
	return string(b)
}
