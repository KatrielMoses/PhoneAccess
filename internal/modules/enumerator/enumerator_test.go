package enumerator

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

type mockHTTPClient struct {
	responses map[string]*http.Response
	errs      map[string]error
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	urlStr := req.URL.String()
	if err, ok := m.errs[urlStr]; ok {
		return nil, err
	}
	if resp, ok := m.responses[urlStr]; ok {
		return resp, nil
	}
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(bytes.NewReader([]byte(`{"registered": false}`))),
	}, nil
}

func mockResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}
}

func TestEnumerator_FoundAndNotFound(t *testing.T) {
	services := []Service{
		{
			Name:     "TestFound",
			Category: CatSocial,
			URL:      "https://api.test.com/check/{DIGITS}",
			Method:   "GET",
			RespCheck: func(body []byte, code int) (bool, string) {
				return bytes.Contains(body, []byte(`"registered":true`)), "@testuser"
			},
		},
		{
			Name:     "TestNotFound",
			Category: CatSocial,
			URL:      "https://api.notfound.com/check/{DIGITS}",
			Method:   "GET",
			RespCheck: func(body []byte, code int) (bool, string) {
				return false, ""
			},
		},
	}

	client := &mockHTTPClient{
		responses: map[string]*http.Response{
			"https://api.test.com/check/14155552671":     mockResponse(200, `{"registered":true}`),
			"https://api.notfound.com/check/14155552671": mockResponse(404, `{"registered":false}`),
		},
	}

	mod := New(WithServices(services), WithHTTPClient(client), WithRateLimiter(core.NewRateLimiter(time.Millisecond)))

	number := &core.PhoneNumber{E164: "+14155552671"}
	res, err := mod.Run(context.Background(), number)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if res.Findings["hit_count"] != "1" {
		t.Errorf("expected 1 hit, got %s", res.Findings["hit_count"])
	}
	if res.Findings["checked"] != "2" {
		t.Errorf("expected 2 checked, got %s", res.Findings["checked"])
	}

	// Test identity graph extraction
	report := &core.InvestigationReport{
		Results: []*core.ModuleResult{res},
	}
	graph := core.BuildIdentityGraph(report)
	foundPivot := false
	for _, p := range graph.PivotPoints {
		if p.Type == "username" && strings.TrimPrefix(p.Value, "@") == "testuser" {
			foundPivot = true
			if p.Confidence != "inference" {
				t.Errorf("expected inference confidence, got %s", p.Confidence)
			}
			break
		}
	}
	if !foundPivot {
		t.Errorf("expected username testuser in identity graph")
	}

	// Test JSON serialization of findings
	data, err := json.Marshal(res.Findings)
	if err != nil {
		t.Errorf("JSON serialization failed: %v", err)
	}
	if !bytes.Contains(data, []byte("hit_count")) {
		t.Errorf("expected hit_count in JSON, got %s", string(data))
	}
}

func TestEnumerator_PassiveModeSkip(t *testing.T) {
	mod := New()
	number := &core.PhoneNumber{E164: "+14155552671"}

	res, err := mod.RunPassive(context.Background(), number)
	if err != nil {
		t.Fatalf("RunPassive failed: %v", err)
	}

	if res.Status != core.ModuleStatusSkipped {
		t.Errorf("expected status skipped, got %s", res.Status)
	}
	if res.Findings["skipped"] != "true" {
		t.Errorf("expected skipped=true, got %v", res.Findings["skipped"])
	}
}

func TestEnumerator_RateLimiter(t *testing.T) {
	services := []Service{
		{
			Name: "Test1", Category: CatSocial, URL: "https://api.rate.com/1",
		},
		{
			Name: "Test2", Category: CatSocial, URL: "https://api.rate.com/2",
		},
	}
	client := &mockHTTPClient{
		responses: map[string]*http.Response{
			"https://api.rate.com/1": mockResponse(200, `{}`),
			"https://api.rate.com/2": mockResponse(200, `{}`),
		},
	}

	delay := 100 * time.Millisecond
	mod := New(WithServices(services), WithHTTPClient(client), WithRateLimiter(core.NewRateLimiter(delay)))

	start := time.Now()
	_, err := mod.Run(context.Background(), &core.PhoneNumber{E164: "+14155552671"})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	duration := time.Since(start)

	if duration < delay {
		t.Errorf("expected duration >= %v, got %v", delay, duration)
	}
}
