package paste

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

type pasteClient struct {
	t      *testing.T
	mu     sync.Mutex
	calls  []*http.Request
	bodyFn func(*http.Request) (string, int)
}

func (c *pasteClient) Do(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.calls = append(c.calls, req.Clone(req.Context()))
	c.mu.Unlock()
	body, status := c.bodyFn(req)
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
	}, nil
}

func TestPsbdmpEmailExtraction(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	number := mustPasteNumber(t)
	client := &pasteClient{
		t: t,
		bodyFn: func(req *http.Request) (string, int) {
			switch {
			case strings.Contains(req.URL.Host, "psbdmp.ws") && strings.Contains(req.URL.Path, "/api/search/"):
				return `[{"id":"abc123","date":"2024-01-02"}]`, http.StatusOK
			case strings.Contains(req.URL.Host, "psbdmp.ws") && strings.Contains(req.URL.Path, "/api/get/abc123"):
				return `{"content":"Jane Roe jane.roe@example.com +1 415 555 2671"}`, http.StatusOK
			default:
				return emptyPasteResponse(req), http.StatusOK
			}
		},
	}

	result, err := New(WithHTTPClient(client), WithNow(func() time.Time { return time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC) })).Run(context.Background(), number)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	data := result.Data.(PasteResult)

	if len(data.PsbdmpHits) != 1 {
		t.Fatalf("psbdmp hits = %#v, want 1", data.PsbdmpHits)
	}
	if !containsString(data.PsbdmpHits[0].Emails, "jane.roe@example.com") {
		t.Fatalf("emails = %#v, want extracted email", data.PsbdmpHits[0].Emails)
	}
	if !strings.Contains(data.PsbdmpHits[0].Preview, "Jane Roe") {
		t.Fatalf("preview = %q, want pasted content preview", data.PsbdmpHits[0].Preview)
	}
}

func TestGitHubUnauthenticatedRateLimitRespected(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GITHUB_TOKEN", "")
	number := mustPasteNumber(t)
	client := &pasteClient{
		t: t,
		bodyFn: func(req *http.Request) (string, int) {
			if strings.Contains(req.URL.Host, "api.github.com") {
				if auth := req.Header.Get("Authorization"); auth != "" {
					t.Fatalf("authorization header = %q, want empty for unauthenticated request", auth)
				}
				return `{"total_count":1,"items":[{"repository":{"full_name":"acme/repo","created_at":"2024-01-01T00:00:00Z"},"path":"notes.txt","html_url":"https://github.com/acme/repo/blob/main/notes.txt"}]}`, http.StatusOK
			}
			return emptyPasteResponse(req), http.StatusOK
		},
	}

	module := New(WithHTTPClient(client), WithNow(time.Now))
	module.githubLimiter = core.NewRateLimiter(50 * time.Millisecond)
	module.redditLimiter = core.NewRateLimiter(0)

	start := time.Now()
	if _, err := module.Run(context.Background(), number); err != nil {
		t.Fatalf("first Run() error = %v", err)
	}
	firstDuration := time.Since(start)

	start = time.Now()
	if _, err := module.Run(context.Background(), number); err != nil {
		t.Fatalf("second Run() error = %v", err)
	}
	secondDuration := time.Since(start)

	if secondDuration < 40*time.Millisecond {
		t.Fatalf("second run duration = %s, want rate-limited delay", secondDuration)
	}
	if firstDuration > secondDuration && firstDuration < 40*time.Millisecond {
		t.Logf("first run completed quickly as expected: %s", firstDuration)
	}
}

func TestRedditTimestampParsedToTimelineEvent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	number := mustPasteNumber(t)
	client := &pasteClient{
		t: t,
		bodyFn: func(req *http.Request) (string, int) {
			if strings.Contains(req.URL.Host, "reddit.com") {
				return `{"data":{"children":[{"data":{"title":"Found +14155552671 on Reddit","subreddit":"r/test","created_utc":1717000000,"url":"https://reddit.com/r/test","score":11,"selftext":"+14155552671 in body"}}]}}`, http.StatusOK
			}
			return emptyPasteResponse(req), http.StatusOK
		},
	}

	result, err := New(WithHTTPClient(client), WithNow(time.Now)).Run(context.Background(), number)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	report := &core.InvestigationReport{
		GeneratedAt: time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC),
		Results:     []*core.ModuleResult{result},
	}
	timeline := core.BuildTimeline(report)

	if len(timeline.Events) == 0 {
		t.Fatalf("timeline events = %#v, want reddit event", timeline.Events)
	}
	if timeline.Events[0].Source != "reddit" {
		t.Fatalf("first event source = %q, want reddit", timeline.Events[0].Source)
	}
	if timeline.Events[0].Date != "2024-05-29" {
		t.Fatalf("event date = %q, want 2024-05-29", timeline.Events[0].Date)
	}
}

func TestIntelXTwoStepUUIDPolling(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("INTELX_API_KEY", "intelx-key")
	number := mustPasteNumber(t)
	client := &pasteClient{
		t: t,
		bodyFn: func(req *http.Request) (string, int) {
			switch {
			case req.Method == http.MethodPost && strings.Contains(req.URL.Host, "2.intelx.io") && strings.Contains(req.URL.Path, "/phonebook/search"):
				return `{"id":"uuid-123"}`, http.StatusOK
			case req.Method == http.MethodGet && strings.Contains(req.URL.Host, "2.intelx.io") && strings.Contains(req.URL.Path, "/phonebook/search/result"):
				return `{"results":[{"source_name":"BreachDB","type":"phonebook","indexdate":"2024-04-05"}]}`, http.StatusOK
			default:
				return emptyPasteResponse(req), http.StatusOK
			}
		},
	}

	result, err := New(WithHTTPClient(client), WithNow(time.Now)).Run(context.Background(), number)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	data := result.Data.(PasteResult)

	if len(data.IntelXHits) != 1 || data.IntelXHits[0].UUID != "uuid-123" {
		t.Fatalf("intelx hits = %#v, want polled UUID result", data.IntelXHits)
	}
	if data.IntelXHits[0].SourceName != "BreachDB" {
		t.Fatalf("intelx source_name = %q, want BreachDB", data.IntelXHits[0].SourceName)
	}
}

func TestDeHashedBasicAuthHeaderCorrectlySet(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("DEHASHED_EMAIL", "user@example.com")
	t.Setenv("DEHASHED_API_KEY", "dehashed-key")
	number := mustPasteNumber(t)
	client := &pasteClient{
		t: t,
		bodyFn: func(req *http.Request) (string, int) {
			if strings.Contains(req.URL.Host, "api.dehashed.com") {
				want := "Basic " + base64.StdEncoding.EncodeToString([]byte("user@example.com:dehashed-key"))
				if got := req.Header.Get("Authorization"); got != want {
					t.Fatalf("authorization = %q, want %q", got, want)
				}
				return `{"entries":[{"database_name":"ExampleDB","email":"jane.roe@example.com","name":"Jane Roe"}]}`, http.StatusOK
			}
			return emptyPasteResponse(req), http.StatusOK
		},
	}

	result, err := New(WithHTTPClient(client), WithNow(time.Now)).Run(context.Background(), number)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	data := result.Data.(PasteResult)

	if len(data.DeHashedHits) != 1 {
		t.Fatalf("dehashed hits = %#v, want one hit", data.DeHashedHits)
	}
	if !containsString(data.Emails, "jane.roe@example.com") {
		t.Fatalf("emails = %#v, want discovered email", data.Emails)
	}
}

func emptyPasteResponse(req *http.Request) string {
	switch {
	case strings.Contains(req.URL.Host, "api.github.com"):
		return `{"total_count":0,"items":[]}`
	case strings.Contains(req.URL.Host, "www.reddit.com"):
		return `{"data":{"children":[]}}`
	case strings.Contains(req.URL.Host, "2.intelx.io"):
		return `{"id":"","uuid":""}`
	case strings.Contains(req.URL.Host, "api.dehashed.com"):
		return `{"entries":[]}`
	default:
		return `[]`
	}
}

func mustPasteNumber(t *testing.T) *core.PhoneNumber {
	t.Helper()
	number, err := core.NormalizePhoneNumber("+14155552671")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return number
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
