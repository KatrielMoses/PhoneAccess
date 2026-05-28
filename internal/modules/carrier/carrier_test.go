package carrier

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

type blockingClient struct {
	t *testing.T
}

func (c blockingClient) Do(req *http.Request) (*http.Response, error) {
	c.t.Fatalf("unexpected network call to %s", req.URL.String())
	return nil, errors.New("unexpected network call")
}

func TestOfflineUSMobileNumber(t *testing.T) {
	number, err := core.NormalizePhoneNumber("+14155552671")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	result := runOffline(t, number)

	if result.Findings["valid"] != "true" {
		t.Fatalf("valid = %q, want true", result.Findings["valid"])
	}
	if result.Findings["line_type"] != string(core.LineTypeMobile) {
		t.Fatalf("line_type = %q, want %q", result.Findings["line_type"], core.LineTypeMobile)
	}
	if result.Findings["international_format"] == "unknown" {
		t.Fatal("international_format should be populated")
	}
}

func TestOfflineUKLandline(t *testing.T) {
	number, err := core.NormalizePhoneNumber("+442079460958")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	result := runOffline(t, number)

	if result.Findings["country"] != "GB" {
		t.Fatalf("country = %q, want GB", result.Findings["country"])
	}
	if result.Findings["line_type"] != string(core.LineTypeLandline) {
		t.Fatalf("line_type = %q, want %q", result.Findings["line_type"], core.LineTypeLandline)
	}
}

func TestInvalidNumberPassthrough(t *testing.T) {
	number := &core.PhoneNumber{
		RawInput: "not-a-number",
		E164:     "not-a-number",
		Valid:    false,
		LineType: core.LineTypeUnknown,
	}

	result := runOffline(t, number)

	if result.Status != core.ModuleStatusSuccess {
		t.Fatalf("status = %q, want success", result.Status)
	}
	if result.Findings["valid"] != "false" {
		t.Fatalf("valid = %q, want false", result.Findings["valid"])
	}
	if result.Findings["line_type"] != string(core.LineTypeUnknown) {
		t.Fatalf("line_type = %q, want unknown", result.Findings["line_type"])
	}
}

func TestTollFreeDetection(t *testing.T) {
	number, err := core.NormalizePhoneNumber("+18005551212")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	result := runOffline(t, number)

	if result.Findings["line_type"] != string(core.LineTypeTollFree) {
		t.Fatalf("line_type = %q, want %q", result.Findings["line_type"], core.LineTypeTollFree)
	}
}

func TestOfflineOnlyModeMakesNoNetworkCalls(t *testing.T) {
	number, err := core.NormalizePhoneNumber("+14155552671")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	result := runOffline(t, number)

	if result.Findings["data_source"] != "offline" {
		t.Fatalf("data_source = %q, want offline", result.Findings["data_source"])
	}
}

func TestTwilioFindingsMergedIntoCarrierModule(t *testing.T) {
	module := New(
		WithTwilioCredentials("AC123", "token123", false),
		WithHTTPClient(twilioCarrierClient{t: t}),
		WithRateLimiter(core.NewRateLimiter(0)),
	)

	result, err := module.Run(context.Background(), mustCarrierNumber(t, "+14155552671"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if got := result.Findings["carrier"]; got != "Twilio Carrier" {
		t.Fatalf("carrier = %q, want Twilio Carrier", got)
	}
	if got := result.Findings["line_type"]; got != string(core.LineTypeMobile) {
		t.Fatalf("line_type = %q, want mobile", got)
	}
	if got := result.Findings["data_source"]; got != "twilio" {
		t.Fatalf("data_source = %q, want twilio", got)
	}
}

func runOffline(t *testing.T, number *core.PhoneNumber) *core.ModuleResult {
	t.Helper()

	module := New(
		WithAPIKeys("", ""),
		WithHTTPClient(blockingClient{t: t}),
		WithRateLimiter(core.NewRateLimiter(0)),
	)
	result, err := module.Run(context.Background(), number)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return result
}

type twilioCarrierClient struct {
	t *testing.T
}

func (c twilioCarrierClient) Do(req *http.Request) (*http.Response, error) {
	if req.URL.Host != "lookups.twilio.com" {
		c.t.Fatalf("host = %q, want lookups.twilio.com", req.URL.Host)
	}
	if !strings.Contains(req.URL.Query().Get("Fields"), "line_type_intelligence") {
		c.t.Fatalf("Fields = %q, want line_type_intelligence", req.URL.Query().Get("Fields"))
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"line_type_intelligence":{"carrier_name":"Twilio Carrier","type":"mobile","mobile_country_code":"310","mobile_network_code":"260"}}`)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}, nil
}

func mustCarrierNumber(t *testing.T, raw string) *core.PhoneNumber {
	t.Helper()
	number, err := core.NormalizePhoneNumber(raw)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return number
}
