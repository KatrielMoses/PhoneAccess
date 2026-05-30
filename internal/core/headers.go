package core

import (
	"fmt"
	"net/http"
)

// profileHeaders returns the browser-profile header set for the given UA entry.
// Module-set headers always win because the RoundTripper only injects headers
// that are not already present on the request.
func profileHeaders(e UAEntry) map[string]string {
	switch e.Profile {
	case "chrome_windows":
		return chromeHeaders(e, `"Windows"`, false)
	case "chrome_macos":
		return chromeHeaders(e, `"macOS"`, false)
	case "chrome_android":
		return chromeHeaders(e, `"Android"`, true)
	case "firefox_windows", "firefox_linux":
		return map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.5",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Dest":  "document",
			"Sec-Fetch-Mode":  "navigate",
			"Sec-Fetch-Site":  "none",
		}
	case "safari_macos":
		// Safari does not send Sec-CH-UA headers.
		return map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.9",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Dest":  "document",
			"Sec-Fetch-Mode":  "navigate",
			"Sec-Fetch-Site":  "none",
		}
	default:
		return map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.9",
			"Accept-Encoding": "gzip, deflate, br",
		}
	}
}

func chromeHeaders(e UAEntry, platform string, mobile bool) map[string]string {
	secCHUA := fmt.Sprintf(`"%s";v="%s", "Chromium";v="%s", "Not-A.Brand";v="99"`, e.Brand, e.Version, e.Version)
	mobileVal := "?0"
	if mobile {
		mobileVal = "?1"
	}
	return map[string]string{
		"Accept":             "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"Accept-Language":    "en-US,en;q=0.9",
		"Accept-Encoding":    "gzip, deflate, br",
		"Sec-CH-UA":          secCHUA,
		"Sec-CH-UA-Mobile":   mobileVal,
		"Sec-CH-UA-Platform": platform,
		"Sec-Fetch-Dest":     "document",
		"Sec-Fetch-Mode":     "navigate",
		"Sec-Fetch-Site":     "none",
	}
}

// headerTransport wraps an http.RoundTripper and injects browser-like headers.
// It uses http.DefaultTransport as the base so it always respects whatever
// proxy was applied after construction.
type headerTransport struct {
	pool *UserAgentPool
	base http.RoundTripper // nil → use http.DefaultTransport at call time
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r2 := req.Clone(req.Context())

	// Determine which UA and profile to use.
	var entry UAEntry
	if r2.Header.Get("User-Agent") == "" {
		var ua string
		ua, entry = t.pool.Get()
		r2.Header.Set("User-Agent", ua)
	} else {
		entry = t.pool.EntryForUA(r2.Header.Get("User-Agent"))
	}

	// Inject profile headers — only where the module has not already set them.
	for k, v := range profileHeaders(entry) {
		if r2.Header.Get(k) == "" {
			r2.Header.Set(k, v)
		}
	}

	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(r2)
}

// NewHeaderTransport wraps pool into an http.RoundTripper that injects browser
// header profiles. Pass nil as base to use http.DefaultTransport dynamically.
func NewHeaderTransport(pool *UserAgentPool, base http.RoundTripper) http.RoundTripper {
	return &headerTransport{pool: pool, base: base}
}
