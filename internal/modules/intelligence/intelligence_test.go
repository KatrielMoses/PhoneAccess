package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

func testNumber(e164, national string) *core.PhoneNumber {
	return &core.PhoneNumber{
		E164:           e164,
		NationalNumber: national,
		CountryCode:    1,
		CountryAlpha2:  "US",
		Valid:           true,
	}
}

// mockServer builds an httptest.Server whose handler is determined by the URL path.
type mockServer struct {
	sanctionsSearchHandler func(w http.ResponseWriter, r *http.Request)
	sanctionsMatchHandler  func(w http.ResponseWriter, r *http.Request)
	mediaHandler           func(w http.ResponseWriter, r *http.Request)
}

func (ms *mockServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.Contains(r.URL.Path, "/search/"):
		if ms.sanctionsSearchHandler != nil {
			ms.sanctionsSearchHandler(w, r)
		} else {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(osSearchResponse{})
		}
	case strings.Contains(r.URL.Path, "/match/"):
		if ms.sanctionsMatchHandler != nil {
			ms.sanctionsMatchHandler(w, r)
		} else {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(osMatchResponse{})
		}
	case strings.Contains(r.URL.Path, "/rss/"):
		if ms.mediaHandler != nil {
			ms.mediaHandler(w, r)
		} else {
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, emptyRSS())
		}
	default:
		http.NotFound(w, r)
	}
}

func emptyRSS() string {
	return `<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel></channel></rss>`
}

func adverseRSS(articles []struct{ title, link, source, date, snippet string }) string {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel>`)
	for _, a := range articles {
		sb.WriteString(`<item>`)
		sb.WriteString(`<title>` + a.title + `</title>`)
		sb.WriteString(`<link>` + a.link + `</link>`)
		sb.WriteString(`<pubDate>` + a.date + `</pubDate>`)
		sb.WriteString(`<description>` + a.snippet + `</description>`)
		sb.WriteString(`<source>` + a.source + `</source>`)
		sb.WriteString(`</item>`)
	}
	sb.WriteString(`</channel></rss>`)
	return sb.String()
}

func sanctionsEntity(id, name string, score float64, datasets []string) osEntity {
	return osEntity{
		ID:     id,
		Schema: "Person",
		Properties: map[string][]string{
			"name": {name},
		},
		Datasets: datasets,
		Score:    score,
	}
}

func searchResponse(entities []osEntity) string {
	b, _ := json.Marshal(osSearchResponse{Results: entities})
	return string(b)
}

// newTestModule builds a Module pointing at a custom test server base URL.
func newTestModule(serverURL string) *Module {
	// Patch the constants by injecting a transport that rewrites the host.
	transport := &rewriteTransport{base: serverURL}
	client := &http.Client{Transport: transport}
	return New(WithHTTPClient(client), WithMediaRateLimiter(0))
}

// rewriteTransport rewrites all requests to go to baseURL, preserving path+query.
type rewriteTransport struct {
	base string
}

func (rt *rewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.URL.Scheme = "http"
	// Extract host from base URL.
	base := strings.TrimPrefix(strings.TrimPrefix(rt.base, "http://"), "https://")
	clone.URL.Host = base
	return http.DefaultTransport.RoundTrip(clone)
}

// TestModuleTierActive verifies the module is TierActive.
func TestModuleTierActive(t *testing.T) {
	m := New()
	if m.Tier() != core.TierActive {
		t.Fatalf("expected TierActive, got %v", m.Tier())
	}
}

// TestSanctionsHighRiskAdds40Points verifies score >= 0.85 adds +40 to risk.
func TestSanctionsHighRiskAdds40Points(t *testing.T) {
	srv := httptest.NewServer(&mockServer{
		sanctionsSearchHandler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			entities := []osEntity{sanctionsEntity("e1", "John Smith", 0.91, []string{"us_ofac_sdn"})}
			fmt.Fprint(w, searchResponse(entities))
		},
	})
	defer srv.Close()

	m := newTestModule(srv.URL)
	result, _ := m.Run(context.Background(), testNumber("+14155550100", "4155550100"))
	intel := result.Data.(IntelligenceResult)

	if !intel.Sanctions.HighRisk {
		t.Error("expected HighRisk = true for score 0.91")
	}
	if len(intel.Sanctions.Hits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(intel.Sanctions.Hits))
	}

	// Verify the risk scorer gives +40.
	report := &core.InvestigationReport{
		Results: []*core.ModuleResult{result},
	}
	driver := sanctionsRiskDriver(report)
	if driver.Points != 40 {
		t.Errorf("expected +40 points for high risk hit, got %d", driver.Points)
	}
}

// TestSanctionsMediumScoreAdds20Points verifies score 0.60-0.84 adds +20.
func TestSanctionsMediumScoreAdds20Points(t *testing.T) {
	srv := httptest.NewServer(&mockServer{
		sanctionsSearchHandler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			entities := []osEntity{sanctionsEntity("e2", "Jane Doe", 0.72, []string{"eu_fsf"})}
			fmt.Fprint(w, searchResponse(entities))
		},
	})
	defer srv.Close()

	m := newTestModule(srv.URL)
	result, _ := m.Run(context.Background(), testNumber("+14155550101", "4155550101"))
	intel := result.Data.(IntelligenceResult)

	if intel.Sanctions.HighRisk {
		t.Error("expected HighRisk = false for score 0.72")
	}

	report := &core.InvestigationReport{Results: []*core.ModuleResult{result}}
	driver := sanctionsRiskDriver(report)
	if driver.Points != 20 {
		t.Errorf("expected +20 points for medium score hit, got %d", driver.Points)
	}
}

// TestSanctionsBelowThresholdFiltered verifies score < 0.60 is not surfaced.
func TestSanctionsBelowThresholdFiltered(t *testing.T) {
	srv := httptest.NewServer(&mockServer{
		sanctionsSearchHandler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			entities := []osEntity{sanctionsEntity("e3", "Noisy Match", 0.45, []string{"us_ofac_sdn"})}
			fmt.Fprint(w, searchResponse(entities))
		},
	})
	defer srv.Close()

	m := newTestModule(srv.URL)
	result, _ := m.Run(context.Background(), testNumber("+14155550102", "4155550102"))
	intel := result.Data.(IntelligenceResult)

	if len(intel.Sanctions.Hits) != 0 {
		t.Errorf("expected 0 hits below threshold, got %d", len(intel.Sanctions.Hits))
	}
}

// TestKeyAbsentUnauthenticatedStillAttempted verifies unauthenticated search
// runs even without OPENSANCTIONS_API_KEY.
func TestKeyAbsentUnauthenticatedStillAttempted(t *testing.T) {
	t.Setenv("OPENSANCTIONS_API_KEY", "")

	var searchCalled int32
	srv := httptest.NewServer(&mockServer{
		sanctionsSearchHandler: func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&searchCalled, 1)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, searchResponse(nil))
		},
		sanctionsMatchHandler: func(w http.ResponseWriter, r *http.Request) {
			t.Error("match endpoint should not be called without API key")
		},
	})
	defer srv.Close()

	m := newTestModule(srv.URL)
	result, _ := m.Run(context.Background(), testNumber("+14155550103", "4155550103"))
	intel := result.Data.(IntelligenceResult)

	if !intel.Sanctions.Screened {
		t.Error("expected Screened=true even without API key")
	}
	if atomic.LoadInt32(&searchCalled) == 0 {
		t.Error("unauthenticated search endpoint was not called")
	}
}

// TestGoogleNewsRSSParsedWithKeywords verifies adverse-keyword filtering works.
func TestGoogleNewsRSSParsedWithKeywords(t *testing.T) {
	articles := []struct{ title, link, source, date, snippet string }{
		{
			title:   "Phone linked to investment fraud scheme",
			link:    "https://example.com/article1",
			source:  "Reuters",
			date:    "Sun, 03 Nov 2024 12:00:00 GMT",
			snippet: "The phone number was linked to a major fraud ring.",
		},
	}

	srv := httptest.NewServer(&mockServer{
		sanctionsSearchHandler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, searchResponse(nil))
		},
		mediaHandler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, adverseRSS(articles))
		},
	})
	defer srv.Close()

	m := newTestModule(srv.URL)
	result, _ := m.Run(context.Background(), testNumber("+14155550104", "4155550104"))
	intel := result.Data.(IntelligenceResult)

	if intel.Media.ArticleCount == 0 {
		t.Error("expected at least one adverse media article")
	}
	if len(intel.Media.Articles) == 0 {
		t.Fatal("articles slice is empty")
	}
	a := intel.Media.Articles[0]
	if !strings.Contains(strings.ToLower(a.Title), "fraud") &&
		!containsKeyword(a.Keywords, "fraud") {
		t.Errorf("expected fraud keyword in article, got title=%q keywords=%v", a.Title, a.Keywords)
	}
}

// TestNoAdverseKeywordsExcluded verifies clean articles are not included.
func TestNoAdverseKeywordsExcluded(t *testing.T) {
	articles := []struct{ title, link, source, date, snippet string }{
		{
			title:   "Local business highlights community event",
			link:    "https://example.com/clean1",
			source:  "Local News",
			date:    "Mon, 04 Nov 2024 12:00:00 GMT",
			snippet: "A community event was held downtown.",
		},
	}

	srv := httptest.NewServer(&mockServer{
		sanctionsSearchHandler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, searchResponse(nil))
		},
		mediaHandler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, adverseRSS(articles))
		},
	})
	defer srv.Close()

	m := newTestModule(srv.URL)
	result, _ := m.Run(context.Background(), testNumber("+14155550105", "4155550105"))
	intel := result.Data.(IntelligenceResult)

	if intel.Media.ArticleCount != 0 {
		t.Errorf("expected 0 articles (no adverse keywords), got %d", intel.Media.ArticleCount)
	}
}

// TestArticleDatesInFindings verifies article pub dates propagate correctly.
func TestArticleDatesInFindings(t *testing.T) {
	articles := []struct{ title, link, source, date, snippet string }{
		{
			title:   "Suspect charged in wire fraud",
			link:    "https://example.com/charged1",
			source:  "BBC News",
			date:    "Sat, 17 Sep 2024 09:00:00 GMT",
			snippet: "Person was charged with wire fraud.",
		},
	}

	srv := httptest.NewServer(&mockServer{
		sanctionsSearchHandler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, searchResponse(nil))
		},
		mediaHandler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, adverseRSS(articles))
		},
	})
	defer srv.Close()

	m := newTestModule(srv.URL)
	result, _ := m.Run(context.Background(), testNumber("+14155550106", "4155550106"))
	intel := result.Data.(IntelligenceResult)

	if intel.Media.ArticleCount == 0 {
		t.Fatal("expected at least 1 article")
	}
	pub := intel.Media.Articles[0].PublishedAt
	if pub.IsZero() {
		t.Error("expected non-zero PublishedAt")
	}
	if pub.Year() != 2024 || pub.Month() != time.September {
		t.Errorf("unexpected article date: %v", pub)
	}
}

// TestThreePlusArticlesAdds20Points verifies 3+ adverse articles adds +20.
func TestThreePlusArticlesAdds20Points(t *testing.T) {
	articles := []struct{ title, link, source, date, snippet string }{
		{title: "Fraud scheme", link: "https://a.com/1", source: "Reuters", date: "Mon, 01 Jan 2024 00:00:00 GMT", snippet: "fraud"},
		{title: "Scam investigation", link: "https://a.com/2", source: "AP", date: "Tue, 02 Jan 2024 00:00:00 GMT", snippet: "scam investigation"},
		{title: "Arrest made", link: "https://a.com/3", source: "BBC", date: "Wed, 03 Jan 2024 00:00:00 GMT", snippet: "arrest"},
	}

	srv := httptest.NewServer(&mockServer{
		sanctionsSearchHandler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, searchResponse(nil))
		},
		mediaHandler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, adverseRSS(articles))
		},
	})
	defer srv.Close()

	m := newTestModule(srv.URL)
	result, _ := m.Run(context.Background(), testNumber("+14155550107", "4155550107"))
	intel := result.Data.(IntelligenceResult)

	if intel.Media.ArticleCount < 3 {
		t.Fatalf("expected >= 3 articles, got %d", intel.Media.ArticleCount)
	}

	report := &core.InvestigationReport{Results: []*core.ModuleResult{result}}
	driver := mediaRiskDriver(report)
	if driver.Points != 20 {
		t.Errorf("expected +20 points for 3+ articles, got %d", driver.Points)
	}
}

// TestOneToTwoArticlesAdds10Points verifies 1-2 adverse articles adds +10.
func TestOneToTwoArticlesAdds10Points(t *testing.T) {
	articles := []struct{ title, link, source, date, snippet string }{
		{title: "Fraud scheme", link: "https://b.com/1", source: "Reuters", date: "Mon, 01 Jan 2024 00:00:00 GMT", snippet: "fraud"},
	}

	srv := httptest.NewServer(&mockServer{
		sanctionsSearchHandler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, searchResponse(nil))
		},
		mediaHandler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, adverseRSS(articles))
		},
	})
	defer srv.Close()

	m := newTestModule(srv.URL)
	result, _ := m.Run(context.Background(), testNumber("+14155550108", "4155550108"))

	report := &core.InvestigationReport{Results: []*core.ModuleResult{result}}
	driver := mediaRiskDriver(report)
	if driver.Points != 10 {
		t.Errorf("expected +10 points for 1 article, got %d", driver.Points)
	}
}

// TestBothSourcesRunConcurrently verifies sanctions and media run in parallel.
// Use E164==NationalNumber so media makes exactly one HTTP request, keeping timing deterministic.
func TestBothSourcesRunConcurrently(t *testing.T) {
	const delay = 80 * time.Millisecond
	var sanctionsCalled, mediaCalled int32

	srv := httptest.NewServer(&mockServer{
		sanctionsSearchHandler: func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&sanctionsCalled, 1)
			time.Sleep(delay)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, searchResponse(nil))
		},
		mediaHandler: func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&mediaCalled, 1)
			time.Sleep(delay)
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, emptyRSS())
		},
	})
	defer srv.Close()

	// NationalNumber == E164 so only one media query is issued.
	m := newTestModule(srv.URL)
	start := time.Now()
	m.Run(context.Background(), testNumber("+14155550109", "+14155550109"))
	elapsed := time.Since(start)

	if atomic.LoadInt32(&sanctionsCalled) == 0 {
		t.Error("sanctions search was not called")
	}
	if atomic.LoadInt32(&mediaCalled) == 0 {
		t.Error("media RSS was not called")
	}
	// If sequential, elapsed >= 2*delay. Concurrent: elapsed < 2*delay.
	if elapsed >= 2*delay {
		t.Errorf("sources appear sequential (elapsed %v >= 2×%v)", elapsed, delay)
	}
}

// TestDryRunSucceeds verifies DryRun does not error.
func TestDryRunSucceeds(t *testing.T) {
	m := New()
	if err := m.DryRun(context.Background(), testNumber("+14155550110", "4155550110")); err != nil {
		t.Errorf("DryRun returned error: %v", err)
	}
}

// --- helpers to call risk driver functions directly ---

// sanctionsRiskDriver mirrors the logic in core/risk_scorer.go for testing.
func sanctionsRiskDriver(report *core.InvestigationReport) core.RiskDriver {
	hitCount := atoiFindings(report, "intelligence", "sanctions_hit_count")
	highRisk := findingEq(report, "intelligence", "sanctions_high_risk", "true")
	switch {
	case highRisk || hitCount > 0 && highRisk:
		return core.RiskDriver{Label: "Sanctions list match", Points: 40}
	case hitCount > 0:
		return core.RiskDriver{Label: "Possible sanctions association", Points: 20}
	default:
		return core.RiskDriver{Label: "Sanctions list match", Points: 0}
	}
}

func mediaRiskDriver(report *core.InvestigationReport) core.RiskDriver {
	count := atoiFindings(report, "intelligence", "media_article_count")
	switch {
	case count >= 3:
		return core.RiskDriver{Label: "Adverse media coverage", Points: 20}
	case count >= 1:
		return core.RiskDriver{Label: "Adverse media coverage", Points: 10}
	default:
		return core.RiskDriver{Label: "Adverse media coverage", Points: 0}
	}
}

func atoiFindings(report *core.InvestigationReport, module, key string) int {
	for _, r := range report.Results {
		if r == nil || r.ModuleName != module {
			continue
		}
		n, _ := strconv.Atoi(strings.TrimSpace(r.Findings[key]))
		return n
	}
	return 0
}

func findingEq(report *core.InvestigationReport, module, key, val string) bool {
	for _, r := range report.Results {
		if r == nil || r.ModuleName != module {
			continue
		}
		return strings.EqualFold(strings.TrimSpace(r.Findings[key]), val)
	}
	return false
}

func containsKeyword(kws []string, kw string) bool {
	for _, k := range kws {
		if strings.EqualFold(k, kw) {
			return true
		}
	}
	return false
}
