package core

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// captureTransport records the headers received by the underlying transport.
type captureTransport struct {
	captured http.Header
}

func (c *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.captured = req.Header.Clone()
	rec := httptest.NewRecorder()
	rec.WriteHeader(http.StatusOK)
	return rec.Result(), nil
}

func newChromeWindowsPool() *UserAgentPool {
	return &UserAgentPool{
		mode: UAModeFixed,
		fixed: UAEntry{
			UA:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
			Profile: "chrome_windows",
			Brand:   "Google Chrome",
			Version: "130",
		},
		entries: []UAEntry{},
	}
}

func newSafariPool() *UserAgentPool {
	return &UserAgentPool{
		mode: UAModeFixed,
		fixed: UAEntry{
			UA:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
			Profile: "safari_macos",
		},
		entries: []UAEntry{},
	}
}

func doRoundTrip(t *testing.T, pool *UserAgentPool, preSet map[string]string) (http.Header, *captureTransport) {
	t.Helper()
	cap := &captureTransport{}
	rt := NewHeaderTransport(pool, cap)
	req, err := http.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for k, v := range preSet {
		req.Header.Set(k, v)
	}
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	return cap.captured, cap
}

func TestChromeUAGetsSec_CH_UAHeaders(t *testing.T) {
	headers, _ := doRoundTrip(t, newChromeWindowsPool(), nil)
	if headers.Get("Sec-CH-UA") == "" {
		t.Error("Chrome UA should produce Sec-CH-UA header, got empty")
	}
	if headers.Get("Sec-CH-UA-Mobile") == "" {
		t.Error("Chrome UA should produce Sec-CH-UA-Mobile header, got empty")
	}
	if headers.Get("Sec-CH-UA-Platform") == "" {
		t.Error("Chrome UA should produce Sec-CH-UA-Platform header, got empty")
	}
}

func TestSafariUADoesNotGetSec_CH_UAHeaders(t *testing.T) {
	headers, _ := doRoundTrip(t, newSafariPool(), nil)
	if headers.Get("Sec-CH-UA") != "" {
		t.Errorf("Safari UA must not produce Sec-CH-UA, got %q", headers.Get("Sec-CH-UA"))
	}
}

func TestModuleAuthorizationHeaderNotOverwritten(t *testing.T) {
	const authVal = "Bearer secret-token"
	headers, _ := doRoundTrip(t, newChromeWindowsPool(), map[string]string{
		"Authorization": authVal,
	})
	if got := headers.Get("Authorization"); got != authVal {
		t.Errorf("Authorization header was overwritten: got %q, want %q", got, authVal)
	}
}

func TestModuleAPIKeyHeaderNotOverwritten(t *testing.T) {
	const keyVal = "my-api-key-123"
	headers, _ := doRoundTrip(t, newChromeWindowsPool(), map[string]string{
		"X-API-Key": keyVal,
	})
	if got := headers.Get("X-API-Key"); got != keyVal {
		t.Errorf("X-API-Key header was overwritten: got %q, want %q", got, keyVal)
	}
}

func TestRoundTripperSetsUserAgentWhenAbsent(t *testing.T) {
	pool := newChromeWindowsPool()
	headers, _ := doRoundTrip(t, pool, nil)
	if headers.Get("User-Agent") == "" {
		t.Error("RoundTripper should inject User-Agent when not set")
	}
}

func TestRoundTripperRespectsExistingUserAgent(t *testing.T) {
	const myUA = "CustomBot/3.0"
	headers, _ := doRoundTrip(t, newChromeWindowsPool(), map[string]string{
		"User-Agent": myUA,
	})
	if got := headers.Get("User-Agent"); got != myUA {
		t.Errorf("pre-set User-Agent %q was overwritten with %q", myUA, got)
	}
}

// Jitter tests

func TestJitterWithinThirtyPercent(t *testing.T) {
	base := 2 * time.Second
	low := time.Duration(float64(base) * 0.70)
	high := time.Duration(float64(base) * 1.30)
	for i := 0; i < 1000; i++ {
		d := jitter(base)
		if d < low || d > high {
			t.Fatalf("jitter(%v) = %v; outside ±30%% band [%v, %v] on iteration %d", base, d, low, high, i)
		}
	}
}

func TestJitterNeverZeroOrNegative(t *testing.T) {
	base := 100 * time.Millisecond
	for i := 0; i < 1000; i++ {
		d := jitter(base)
		if d <= 0 {
			t.Fatalf("jitter(%v) = %v; must be positive (iteration %d)", base, d, i)
		}
	}
}

// BenchmarkRoundTripperWithHeaders measures header-injection overhead against a
// no-op transport. The goal is to stay within 2% of bare transport cost.
func BenchmarkRoundTripperWithHeaders(b *testing.B) {
	pool := newChromeWindowsPool()
	cap := &captureTransport{}
	rt := NewHeaderTransport(pool, cap)
	req, _ := http.NewRequest("GET", "http://example.com/", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = rt.RoundTrip(req)
	}
}

func BenchmarkBareTransport(b *testing.B) {
	cap := &captureTransport{}
	req, _ := http.NewRequest("GET", "http://example.com/", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cap.RoundTrip(req)
	}
}
