package abstractapi

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/KatrielMoses/PhoneAccess/internal/correlator"
)

type fakeClient struct {
	check func(*http.Request)
	body  string
}

func (c fakeClient) Do(req *http.Request) (*http.Response, error) {
	if c.check != nil {
		c.check(req)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(c.body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}, nil
}

func TestAbstractAPITimezoneArrayUsesFirstElement(t *testing.T) {
	source := New(
		WithAPIKey("abc123"),
		WithBaseURL("https://example.test/v1/"),
		WithHTTPClient(fakeClient{body: `{
			"valid": true,
			"carrier": "Example Carrier",
			"type": "voip",
			"location": "New York",
			"country": {"code":"US","name":"United States"},
			"timezone": ["America/New_York", "America/Chicago"]
		}`}),
	)

	claims, err := source.Fetch(context.Background(), "+14155552671")
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if got := claimValue(claims, "timezone"); got != "America/New_York" {
		t.Fatalf("timezone claim = %q, want first array entry", got)
	}
	if got := claimValue(claims, "carrier"); got != "Example Carrier" {
		t.Fatalf("carrier claim = %q, want Example Carrier", got)
	}
}

func TestAbstractAPIDryRunMissingKey(t *testing.T) {
	source := New(WithAPIKey(""))
	if err := source.DryRun(context.Background(), "+14155552671"); err == nil {
		t.Fatal("DryRun() error = nil, want missing key")
	}
}

func claimValue(claims []correlator.PIIClaim, field string) string {
	for _, claim := range claims {
		if claim.Field == field {
			return claim.Value
		}
	}
	return ""
}
