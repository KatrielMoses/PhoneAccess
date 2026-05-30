package breach

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

// hibpMockClient matches requests by URL prefix so tests don't need to compute
// the exact URL-encoded phone number.
type hibpMockClient struct {
	t        *testing.T
	handler  func(req *http.Request) (*http.Response, error)
	calls    int
}

func (c *hibpMockClient) Do(req *http.Request) (*http.Response, error) {
	c.calls++
	return c.handler(req)
}

func hibpOKResponse(body string) func(*http.Request) (*http.Response, error) {
	return func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	}
}

func hibpStatusResponse(code int) func(*http.Request) (*http.Response, error) {
	return func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: code,
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}
}

func noDelayHIBP() *hibpSource {
	return &hibpSource{minDelay: 0}
}

func TestHIBPHitReturnsBranchEntries(t *testing.T) {
	t.Setenv("HIBP_API_KEY", "test-key")
	number := mustNumber(t)

	body := `[
		{"Name":"Adobe","Title":"Adobe","BreachDate":"2013-10-04","DataClasses":["Email addresses","Passwords"]},
		{"Name":"LinkedIn","Title":"LinkedIn","BreachDate":"2012-05-05","DataClasses":["Email addresses","Passwords","Usernames"]}
	]`

	source := noDelayHIBP()
	client := &hibpMockClient{t: t, handler: hibpOKResponse(body)}

	module := New(
		WithHTTPClient(client),
		WithRateLimiter(core.NewRateLimiter(0)),
		WithSources(source),
	)
	result, err := module.Run(context.Background(), number)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	data := result.Data.(BreachResult)

	if !data.Found {
		t.Fatalf("found = false, want true")
	}
	if data.BreachCount != 2 {
		t.Fatalf("breach_count = %d, want 2", data.BreachCount)
	}
	if data.SourceStatuses["HIBP"] != "hit" {
		t.Fatalf("HIBP status = %q, want hit", data.SourceStatuses["HIBP"])
	}
	// Verify source_api field set to HIBP.
	for _, entry := range data.Breaches {
		if entry.SourceAPI != "HIBP" {
			t.Fatalf("breach %q has source_api = %q, want HIBP", entry.Name, entry.SourceAPI)
		}
	}
	// DataClasses should be merged.
	if !contains(data.DataClassesSeen, "Email addresses") {
		t.Fatalf("DataClassesSeen missing Email addresses: %v", data.DataClassesSeen)
	}
}

func TestHIBP404ReturnsCleanResult(t *testing.T) {
	t.Setenv("HIBP_API_KEY", "test-key")
	number := mustNumber(t)

	source := noDelayHIBP()
	client := &hibpMockClient{t: t, handler: hibpStatusResponse(http.StatusNotFound)}

	module := New(
		WithHTTPClient(client),
		WithRateLimiter(core.NewRateLimiter(0)),
		WithSources(source),
	)
	result, err := module.Run(context.Background(), number)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	data := result.Data.(BreachResult)

	if data.Found {
		t.Fatalf("found = true, want false (404 = clean)")
	}
	if data.SourceStatuses["HIBP"] != "no results" {
		t.Fatalf("HIBP status = %q, want 'no results'", data.SourceStatuses["HIBP"])
	}
}

func TestHIBP401SurfacesKeyError(t *testing.T) {
	t.Setenv("HIBP_API_KEY", "bad-key")
	number := mustNumber(t)

	source := noDelayHIBP()
	client := &hibpMockClient{t: t, handler: hibpStatusResponse(http.StatusUnauthorized)}

	module := New(
		WithHTTPClient(client),
		WithRateLimiter(core.NewRateLimiter(0)),
		WithSources(source),
	)
	result, err := module.Run(context.Background(), number)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	data := result.Data.(BreachResult)

	status := data.SourceStatuses["HIBP"]
	if !strings.Contains(status, "unavailable") {
		t.Fatalf("HIBP status = %q, want unavailable with key message", status)
	}
	if !strings.Contains(status, "401") {
		t.Fatalf("HIBP status = %q, want 401 mentioned", status)
	}
}

func TestHIBP429RetriesOnceThenMarksUnavailable(t *testing.T) {
	t.Setenv("HIBP_API_KEY", "test-key")
	number := mustNumber(t)

	// Both calls return 429 → source ends up unavailable after single retry.
	source := noDelayHIBP()
	client := &hibpMockClient{t: t, handler: hibpStatusResponse(http.StatusTooManyRequests)}

	module := New(
		WithHTTPClient(client),
		WithRateLimiter(core.NewRateLimiter(0)),
		WithSources(source),
	)
	result, err := module.Run(context.Background(), number)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	data := result.Data.(BreachResult)

	// Should have retried exactly once (2 total HTTP calls).
	if client.calls != 2 {
		t.Fatalf("http calls = %d, want 2 (initial + one retry)", client.calls)
	}
	status := data.SourceStatuses["HIBP"]
	if !strings.Contains(status, "unavailable") {
		t.Fatalf("HIBP status = %q, want unavailable after exhausted retry", status)
	}
}

func TestHIBP429FirstThenOKReturnsHit(t *testing.T) {
	t.Setenv("HIBP_API_KEY", "test-key")
	number := mustNumber(t)

	body := `[{"Name":"TestBreachDB","BreachDate":"2024-01-01","DataClasses":["Passwords"]}]`
	call := 0
	handler := func(req *http.Request) (*http.Response, error) {
		call++
		if call == 1 {
			return &http.Response{StatusCode: http.StatusTooManyRequests, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
	}

	source := noDelayHIBP()
	client := &hibpMockClient{t: t, handler: handler}

	module := New(
		WithHTTPClient(client),
		WithRateLimiter(core.NewRateLimiter(0)),
		WithSources(source),
	)
	result, err := module.Run(context.Background(), number)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	data := result.Data.(BreachResult)

	if client.calls != 2 {
		t.Fatalf("http calls = %d, want 2", client.calls)
	}
	if !data.Found {
		t.Fatalf("found = false after 429+retry, want true")
	}
}

func TestHIBPKeyAbsentSkipsCleanly(t *testing.T) {
	t.Setenv("HIBP_API_KEY", "")
	number := mustNumber(t)

	source := noDelayHIBP()
	// blockingClient panics if any HTTP call is made.
	module := New(
		WithHTTPClient(blockingClient{t: t}),
		WithRateLimiter(core.NewRateLimiter(0)),
		WithSources(source),
	)
	result, err := module.Run(context.Background(), number)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	data := result.Data.(BreachResult)

	if data.Found {
		t.Fatalf("found = true, want false when key absent")
	}
	status := data.SourceStatuses["HIBP"]
	if !strings.Contains(status, "unavailable") {
		t.Fatalf("HIBP status = %q, want unavailable when key absent", status)
	}
}

func TestHIBPRateLimitEnforced(t *testing.T) {
	t.Setenv("HIBP_API_KEY", "test-key")
	number := mustNumber(t)

	body := `[{"Name":"Breach1","BreachDate":"2023-01-01","DataClasses":["Passwords"]}]`

	// Use a real delay of 50ms to verify the enforcer fires (full 1500ms would be too slow).
	const testDelay = 50 * time.Millisecond
	source := &hibpSource{minDelay: testDelay}
	client := &hibpMockClient{t: t, handler: hibpOKResponse(body)}

	module := New(
		WithHTTPClient(client),
		WithRateLimiter(core.NewRateLimiter(0)),
		WithSources(source),
	)

	start := time.Now()
	// First call — no delay (lastReq is zero).
	if _, err := module.Run(context.Background(), number); err != nil {
		t.Fatalf("first run: %v", err)
	}
	// Second call — should wait testDelay.
	if _, err := module.Run(context.Background(), number); err != nil {
		t.Fatalf("second run: %v", err)
	}
	elapsed := time.Since(start)

	if elapsed < testDelay {
		t.Fatalf("elapsed = %v, want >= %v (rate limit not enforced)", elapsed, testDelay)
	}
}
