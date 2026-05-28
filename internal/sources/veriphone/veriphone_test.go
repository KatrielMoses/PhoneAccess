package veriphone

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

func TestVeriphoneHit(t *testing.T) {
	source := New(
		WithAPIKey("vp-key"),
		WithBaseURL("https://example.test/v2/verify"),
		WithHTTPClient(fakeClient{body: `{
			"phone_valid": true,
			"phone_type": "mobile",
			"phone_region": "California",
			"country": "United States",
			"country_code": "US",
			"carrier": "Example Wireless"
		}`}),
	)

	claims, err := source.Fetch(context.Background(), "+14155552671")
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if got := claimValue(claims, correlator.FieldCarrier); got != "Example Wireless" {
		t.Fatalf("carrier claim = %q, want Example Wireless", got)
	}
	if got := claimValue(claims, correlator.FieldLineType); got != "mobile" {
		t.Fatalf("line type claim = %q, want mobile", got)
	}
	if got := claimValue(claims, correlator.FieldRegion); got != "California" {
		t.Fatalf("region claim = %q, want California", got)
	}
}

func TestVeriphoneDryRunMissingKeySkips(t *testing.T) {
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
