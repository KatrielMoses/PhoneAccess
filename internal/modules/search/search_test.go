package search

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

type searchClient struct {
	t      *testing.T
	mu     sync.Mutex
	calls  []string
	bodyFn func(*http.Request) (string, int)
}

func (c *searchClient) Do(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.calls = append(c.calls, req.URL.String())
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

func TestSearchQueriesIncludeAllVariantsAndOperators(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOOGLE_CSE_API_KEY", "google-key")
	t.Setenv("GOOGLE_CSE_CX", "google-cx")
	t.Setenv("BING_SEARCH_API_KEY", "bing-key")
	number, err := core.NormalizePhoneNumber("+14155552671")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	client := &searchClient{
		t: t,
		bodyFn: func(req *http.Request) (string, int) {
			if strings.Contains(req.URL.Host, "googleapis.com") {
				return `{"items":[]}`, http.StatusOK
			}
			if strings.Contains(req.URL.Host, "bing.microsoft.com") {
				return `{"webPages":{"value":[]}}`, http.StatusOK
			}
			t.Fatalf("unexpected host: %s", req.URL.Host)
			return "", http.StatusInternalServerError
		},
	}

	result, err := New(WithHTTPClient(client), WithNow(func() time.Time { return time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC) })).Run(context.Background(), number)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	data := result.Data.(SearchResult)

	if len(client.calls) != 18 {
		t.Fatalf("calls = %d, want 18", len(client.calls))
	}
	variants := core.SearchVariantsFor(number)
	for _, rawURL := range client.calls {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			t.Fatalf("parse url %q: %v", rawURL, err)
		}
		query := parsed.Query().Get("q")
		if query == "" {
			t.Fatalf("query missing in %s", rawURL)
		}
		for _, variant := range variants {
			if !strings.Contains(query, variant) {
				t.Fatalf("query %q missing variant %q", query, variant)
			}
		}
	}

	required := []string{
		"site:pastebin.com",
		"site:ghostbin.co",
		"site:craigslist.org",
		"site:reddit.com",
		"site:bbb.org",
		"site:yelp.com",
		"site:courtlistener.com",
		"filetype:pdf site:*.gov",
		"ext:pdf",
	}
	for _, want := range required {
		found := false
		for _, rawURL := range client.calls {
			parsed, _ := url.Parse(rawURL)
			if strings.Contains(parsed.Query().Get("q"), want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected query containing %q", want)
		}
	}
	if data.SourceStatuses["google.paste_sites"] == "" || data.SourceStatuses["bing.paste_sites"] == "" {
		t.Fatalf("source statuses missing expected keys: %#v", data.SourceStatuses)
	}
}

func TestSearchRunsBingAndGoogleInParallel(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOOGLE_CSE_API_KEY", "google-key")
	t.Setenv("GOOGLE_CSE_CX", "google-cx")
	t.Setenv("BING_SEARCH_API_KEY", "bing-key")
	number, err := core.NormalizePhoneNumber("+14155552671")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	var mu sync.Mutex
	active := 0
	release := make(chan struct{})
	var releaseOnce sync.Once
	started := make(chan struct{}, 32)
	client := &searchClient{
		t: t,
		bodyFn: func(req *http.Request) (string, int) {
			mu.Lock()
			active++
			started <- struct{}{}
			if active == 2 {
				releaseOnce.Do(func() { close(release) })
			}
			mu.Unlock()

			if active == 1 {
				<-release
			}

			mu.Lock()
			active--
			mu.Unlock()

			if strings.Contains(req.URL.Host, "googleapis.com") {
				return `{"items":[]}`, http.StatusOK
			}
			if strings.Contains(req.URL.Host, "bing.microsoft.com") {
				return `{"webPages":{"value":[]}}`, http.StatusOK
			}
			t.Fatalf("unexpected host: %s", req.URL.Host)
			return "", http.StatusInternalServerError
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = New(WithHTTPClient(client), WithNow(time.Now)).Run(ctx, number)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(started) < 2 {
		t.Fatalf("parallel calls = %d, want at least 2 overlapping starts", len(started))
	}
}

func TestSearchSignalExtractionFindsEmailInSnippet(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOOGLE_CSE_API_KEY", "google-key")
	t.Setenv("GOOGLE_CSE_CX", "google-cx")
	number, err := core.NormalizePhoneNumber("+14155552671")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	client := &searchClient{
		t: t,
		bodyFn: func(req *http.Request) (string, int) {
			if strings.Contains(req.URL.Host, "googleapis.com") {
				return `{"items":[{"title":"Jane Roe profile","snippet":"Email jane.roe@example.com, site https://example.com/profile","link":"https://example.com/profile"}]}`, http.StatusOK
			}
			return `{"webPages":{"value":[]}}`, http.StatusOK
		},
	}

	result, err := New(WithHTTPClient(client), WithNow(time.Now)).Run(context.Background(), number)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	data := result.Data.(SearchResult)

	if !containsString(data.Emails, "jane.roe@example.com") {
		t.Fatalf("emails = %#v, want jane.roe@example.com", data.Emails)
	}
	if !containsString(data.Names, "Jane Roe") {
		t.Fatalf("names = %#v, want Jane Roe", data.Names)
	}
	if !containsString(data.SocialLinks, "https://example.com/profile") {
		t.Fatalf("social_links = %#v, want example.com profile", data.SocialLinks)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
