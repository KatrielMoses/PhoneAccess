package truecaller

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

type fakeClient struct {
	check  func(*http.Request)
	status int
	body   string
}

func (c fakeClient) Do(req *http.Request) (*http.Response, error) {
	if c.check != nil {
		c.check(req)
	}
	status := c.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(c.body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}, nil
}

func TestTruecallerHitWithNameAndEmailPivot(t *testing.T) {
	module := New(
		WithInstallationID("session-123"),
		WithQuotaStore(memoryQuotaStoreWithData(nil)),
		WithNow(func() time.Time { return time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC) }),
		WithEndpoints("https://search5-noneu.truecaller.com/v2/search", "https://search5-eu.truecaller.com/v2/search"),
		WithHTTPClient(fakeClient{
			body: `{
				"data": [{
					"name": "Jane Roe",
					"score": 0.93,
					"tags": ["telemarketer"],
					"phones": [{"numberType": "mobile"}],
					"addresses": [{"city": "San Francisco", "countryCode": "US", "timeZone": "America/Los_Angeles"}],
					"internetAddresses": ["jane.roe@example.com"],
					"company": "Example Co",
					"jobTitle": "Manager"
				}]
			}`,
		}),
	)

	result, err := module.Run(context.Background(), mustNumber(t, "+14155552671"))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	data := result.Data.(Result)
	if data.Name != "Jane Roe" {
		t.Fatalf("Name = %q, want Jane Roe", data.Name)
	}
	if data.City != "San Francisco" {
		t.Fatalf("City = %q, want San Francisco", data.City)
	}
	if len(data.Emails) != 1 || data.Emails[0] != "jane.roe@example.com" {
		t.Fatalf("Emails = %v, want pivot email", data.Emails)
	}
	if got := result.Findings["email_pivots"]; got != "jane.roe@example.com" {
		t.Fatalf("email_pivots = %q, want pivot email", got)
	}
}

func TestTruecallerSessionExpiredError(t *testing.T) {
	module := New(
		WithInstallationID("session-123"),
		WithQuotaStore(memoryQuotaStoreWithData(nil)),
		WithNow(func() time.Time { return time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC) }),
		WithHTTPClient(fakeClient{status: http.StatusUnauthorized, body: `{"error":"expired"}`}),
	)

	_, err := module.Run(context.Background(), mustNumber(t, "+14155552671"))
	if err == nil || !strings.Contains(err.Error(), "Truecaller session expired") {
		t.Fatalf("error = %v, want session expired message", err)
	}
}

func TestTruecallerDryRunMissingCredentialsIncludesDisclaimer(t *testing.T) {
	module := New(WithInstallationID(""))
	err := module.DryRun(context.Background(), mustNumber(t, "+14155552671"))
	if err == nil || !strings.Contains(err.Error(), "unofficial session token") {
		t.Fatalf("DryRun error = %v, want disclaimer", err)
	}
}

func TestTruecallerEUEndpointRouting(t *testing.T) {
	var gotHost string
	module := New(
		WithInstallationID("session-123"),
		WithQuotaStore(memoryQuotaStoreWithData(nil)),
		WithNow(func() time.Time { return time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC) }),
		WithHTTPClient(fakeClient{
			check: func(req *http.Request) {
				gotHost = req.URL.Host
			},
			body: `{"data":[]}`,
		}),
	)

	_, err := module.Run(context.Background(), mustNumber(t, "+442079460958"))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if gotHost != "search5-eu.truecaller.com" {
		t.Fatalf("host = %q, want EU endpoint", gotHost)
	}
}

func TestTruecallerRateLimitEnforcedAt100Lookups(t *testing.T) {
	module := New(
		WithInstallationID("session-123"),
		WithQuotaStore(memoryQuotaStoreWithData(nil)),
		WithNow(func() time.Time { return time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC) }),
		WithHTTPClient(fakeClient{body: `{"data":[]}`}),
	)

	number := mustNumber(t, "+14155552671")
	for i := 0; i < maxDailyLookups; i++ {
		if _, err := module.Run(context.Background(), number); err != nil {
			t.Fatalf("Run #%d error = %v", i+1, err)
		}
	}

	_, err := module.Run(context.Background(), number)
	if err == nil || !strings.Contains(err.Error(), "Truecaller daily limit reached") {
		t.Fatalf("limit error = %v, want daily limit message", err)
	}
}

func mustNumber(t *testing.T, raw string) *core.PhoneNumber {
	t.Helper()
	number, err := core.NormalizePhoneNumber(raw)
	if err != nil {
		t.Fatalf("NormalizePhoneNumber(%q) error = %v", raw, err)
	}
	return number
}
