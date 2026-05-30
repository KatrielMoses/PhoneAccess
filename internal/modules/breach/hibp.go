package breach

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

// hibpMinDelay is the hard minimum between HIBP API requests. HIBP enforces
// 1,500 ms server-side and returns 429 for faster requests.
const hibpMinDelay = 1500 * time.Millisecond

type hibpSource struct {
	mu       sync.Mutex
	lastReq  time.Time
	minDelay time.Duration // override in tests (0 = no delay)
}

func (s *hibpSource) Name() string { return "HIBP" }

func (s *hibpSource) URL(number *core.PhoneNumber) string {
	return "https://haveibeenpwned.com/api/v3/breachedaccount/" + url.PathEscape(e164(number))
}

func (s *hibpSource) PrepareRequest(ctx context.Context, req *http.Request) error {
	key := core.GetAPIKey(ctx, "HIBP_API_KEY")
	if key == "" {
		return fmt.Errorf("HIBP_API_KEY not configured")
	}
	req.Header.Set("hibp-api-key", key)
	return nil
}

type hibpBreach struct {
	Name        string   `json:"Name"`
	Title       string   `json:"Title"`
	BreachDate  string   `json:"BreachDate"`
	DataClasses []string `json:"DataClasses"`
}

func (s *hibpSource) Parse(body []byte) SourceResult {
	var breaches []hibpBreach
	if err := json.Unmarshal(body, &breaches); err != nil {
		return SourceResult{}
	}
	entries := make([]BreachEntry, 0, len(breaches))
	for _, b := range breaches {
		name := firstNonEmpty(b.Name, b.Title)
		if name == "" {
			continue
		}
		entries = append(entries, BreachEntry{
			Name:        name,
			Date:        b.BreachDate,
			DataClasses: b.DataClasses,
			SourceAPI:   "HIBP",
		})
	}
	return SourceResult{Breaches: entries}
}

func (s *hibpSource) ProxyAware() bool { return true }

// Query implements SourceQuerier. It enforces the 1,500 ms HIBP rate limit,
// handles 401 (bad key) and 429 (rate-limited, single retry) specially.
func (s *hibpSource) Query(ctx context.Context, client HTTPClient, number *core.PhoneNumber) SourceResult {
	key := core.GetAPIKey(ctx, "HIBP_API_KEY")
	if key == "" {
		return SourceResult{Available: false, Error: "HIBP_API_KEY not configured"}
	}

	if err := s.enforceRateLimit(ctx); err != nil {
		return SourceResult{Available: false, Error: err.Error()}
	}

	result, retry := s.execute(ctx, client, key, e164(number))
	if !retry {
		return result
	}

	// 429: wait hibpMinDelay then retry once.
	delay := s.delay()
	select {
	case <-ctx.Done():
		return SourceResult{Available: false, Error: ctx.Err().Error()}
	case <-time.After(delay):
	}

	result, _ = s.execute(ctx, client, key, e164(number))
	if !result.Available && result.Error == "" {
		result.Error = "rate-limited; retry also returned non-200"
	}
	return result
}

// enforceRateLimit blocks until hibpMinDelay has elapsed since the last request.
func (s *hibpSource) enforceRateLimit(ctx context.Context) error {
	delay := s.delay()
	if delay == 0 {
		return nil
	}

	s.mu.Lock()
	elapsed := time.Since(s.lastReq)
	wait := delay - elapsed
	if wait <= 0 {
		s.lastReq = time.Now()
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(wait):
	}

	s.mu.Lock()
	s.lastReq = time.Now()
	s.mu.Unlock()
	return nil
}

func (s *hibpSource) delay() time.Duration {
	if s.minDelay > 0 {
		return s.minDelay
	}
	return hibpMinDelay
}

// execute performs one HTTP request and returns (result, retryNeeded).
func (s *hibpSource) execute(ctx context.Context, client HTTPClient, key, phone string) (SourceResult, bool) {
	endpoint := "https://haveibeenpwned.com/api/v3/breachedaccount/" + url.PathEscape(phone)
	reqCtx, cancel := context.WithTimeout(ctx, core.DefaultHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return SourceResult{Available: false, Error: err.Error()}, false
	}
	core.SetDefaultHeaders(req)
	req.Header.Set("hibp-api-key", key)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return SourceResult{Available: false, Error: err.Error()}, false
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		// Clean result: number not found in any breach.
		return SourceResult{Available: true}, false
	case http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
		if err != nil {
			return SourceResult{Available: false, Error: err.Error()}, false
		}
		result := s.Parse(body)
		result.Available = true
		return result, false
	case http.StatusUnauthorized:
		return SourceResult{Available: false, Error: "HIBP_API_KEY is invalid or expired (HTTP 401)"}, false
	case http.StatusTooManyRequests:
		return SourceResult{}, true // caller will retry after delay
	default:
		return SourceResult{Available: false, Error: fmt.Sprintf("http status %d", resp.StatusCode)}, false
	}
}
