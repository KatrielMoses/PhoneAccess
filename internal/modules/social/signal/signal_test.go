package signal

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

type mockHTTPClient struct {
	t       *testing.T
	handler func(req *http.Request) (*http.Response, error)
	calls   []string
}

func (c *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	c.calls = append(c.calls, req.URL.String())
	return c.handler(req)
}

func statusClient(t *testing.T, code int) *mockHTTPClient {
	return &mockHTTPClient{
		t: t,
		handler: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: code,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		},
	}
}

func testModule(client HTTPClient) *Module {
	return New(
		WithHTTPClient(client),
		WithRateLimiter(core.NewRateLimiter(0)),
	)
}

func testNumber(t *testing.T) *core.PhoneNumber {
	t.Helper()
	num, err := core.NormalizePhoneNumber("+14155552671")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return num
}

func TestSignalFound(t *testing.T) {
	client := statusClient(t, http.StatusOK)
	m := testModule(client)

	result, err := m.Run(context.Background(), testNumber(t))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.Status != core.ModuleStatusSuccess {
		t.Fatalf("status = %q, want success", result.Status)
	}
	if result.Findings["found"] != "true" {
		t.Fatalf("found = %q, want true", result.Findings["found"])
	}

	account := result.Data.(*core.MessengerAccount)
	if !account.Found {
		t.Fatalf("account.Found = false, want true")
	}
	if account.DataSource != "signal_cdn" {
		t.Fatalf("data_source = %q, want signal_cdn", account.DataSource)
	}
	if len(client.calls) != 1 {
		t.Fatalf("http calls = %d, want 1", len(client.calls))
	}
	// URL must contain the HMAC hash, not the raw phone number.
	if strings.Contains(client.calls[0], "+14155552671") {
		t.Fatalf("URL should not contain raw phone number: %s", client.calls[0])
	}
	if !strings.HasPrefix(client.calls[0], cdnBase) {
		t.Fatalf("URL prefix wrong: %s", client.calls[0])
	}
}

func TestSignalNotFound(t *testing.T) {
	client := statusClient(t, http.StatusNotFound)
	m := testModule(client)

	result, err := m.Run(context.Background(), testNumber(t))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.Findings["found"] != "false" {
		t.Fatalf("found = %q, want false", result.Findings["found"])
	}
	account := result.Data.(*core.MessengerAccount)
	if account.Found {
		t.Fatalf("account.Found = true, want false")
	}
}

func TestSignalUnavailableGraceful(t *testing.T) {
	errClient := &mockHTTPClient{
		t: t,
		handler: func(req *http.Request) (*http.Response, error) {
			return nil, &networkError{"simulated network error"}
		},
	}
	m := testModule(errClient)

	result, err := m.Run(context.Background(), testNumber(t))
	// Run should never propagate the error — it returns a module-level error result.
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
	if result.Status != core.ModuleStatusError {
		t.Fatalf("status = %q, want error", result.Status)
	}
}

func TestSignalDryRunAlwaysPasses(t *testing.T) {
	m := testModule(statusClient(t, http.StatusOK))
	if err := m.DryRun(context.Background(), testNumber(t)); err != nil {
		t.Fatalf("DryRun returned error: %v", err)
	}
}

func TestSignalHashIsDeterministic(t *testing.T) {
	h1 := hashPhone("+14155552671")
	h2 := hashPhone("+14155552671")
	if h1 != h2 {
		t.Fatalf("hashPhone not deterministic: %q != %q", h1, h2)
	}
	h3 := hashPhone("+14155552672") // different number
	if h1 == h3 {
		t.Fatalf("hashPhone collision between different numbers")
	}
}

func TestSignalHashIsBase64(t *testing.T) {
	h := hashPhone("+14155552671")
	// base64 standard encoding uses A-Z, a-z, 0-9, +, /, = characters.
	for _, ch := range h {
		if !isBase64Char(ch) {
			t.Fatalf("hash contains non-base64 character %q in %q", ch, h)
		}
	}
}

func isBase64Char(r rune) bool {
	return (r >= 'A' && r <= 'Z') ||
		(r >= 'a' && r <= 'z') ||
		(r >= '0' && r <= '9') ||
		r == '+' || r == '/' || r == '='
}

type networkError struct{ msg string }

func (e *networkError) Error() string { return e.msg }
