package voip

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/carrier"
)

type blockingClient struct {
	t *testing.T
}

func (c blockingClient) Do(req *http.Request) (*http.Response, error) {
	c.t.Fatalf("unexpected network call to %s", req.URL.String())
	return nil, errors.New("unexpected network call")
}

func TestConfirmedVOIPNumberFromEmbeddedPrefix(t *testing.T) {
	number := &core.PhoneNumber{
		E164:           "+15005551234",
		CountryCode:    1,
		CountryAlpha2:  "US",
		NationalNumber: "5005551234",
		LineType:       core.LineTypeUnknown,
		Valid:          true,
	}

	result := runOffline(t, number)
	data := result.Data.(Result)

	if !data.IsVOIP {
		t.Fatal("IsVOIP = false, want true")
	}
	if data.Provider != "Twilio" {
		t.Fatalf("Provider = %q, want Twilio", data.Provider)
	}
	if data.Confidence != "high" {
		t.Fatalf("Confidence = %q, want high", data.Confidence)
	}
}

func TestNonVOIPMobile(t *testing.T) {
	number := &core.PhoneNumber{
		E164:           "+14155552671",
		CountryCode:    1,
		CountryAlpha2:  "US",
		NationalNumber: "4155552671",
		LineType:       core.LineTypeMobile,
		Valid:          true,
	}

	result := runOffline(t, number)
	data := result.Data.(Result)

	if data.IsVOIP {
		t.Fatal("IsVOIP = true, want false")
	}
	if data.Provider != defaultNoProvider {
		t.Fatalf("Provider = %q, want unknown", data.Provider)
	}
}

func TestPrepaidDetectionFromIPQS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"valid": true,
			"line_type": "mobile",
			"risky": false,
			"recent_abuse": false,
			"voip": false,
			"prepaid": true,
			"active": true,
			"carrier": "Example Mobile",
			"country": "US"
		}`))
	}))
	defer server.Close()

	module := New(
		WithAPIKeys("ipqs-key", ""),
		WithEndpoints(server.URL, ""),
		WithRateLimiter(core.NewRateLimiter(0)),
	)
	result, err := module.Run(core.ContextWithResponseCache(context.Background(), core.NewResponseCache()), mobileNumber())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	data := result.Data.(Result)

	if data.IsPrepaid != true {
		t.Fatal("IsPrepaid = false, want true")
	}
	if !strings.Contains(strings.Join(data.RiskSignals, "\n"), "prepaid") {
		t.Fatalf("RiskSignals = %v, want prepaid signal", data.RiskSignals)
	}
	if data.IsVOIP {
		t.Fatal("IsVOIP = true, want false")
	}
}

func TestPassiveSkipSuppressesNetworkCalls(t *testing.T) {
	module := New(
		WithAPIKeys("ipqs-key", "abstract-key"),
		WithHTTPClient(blockingClient{t: t}),
		WithRateLimiter(core.NewRateLimiter(0)),
	)
	result, err := module.RunPassive(context.Background(), mobileNumber())
	if err != nil {
		t.Fatalf("run passive: %v", err)
	}
	if result.Findings["passive"] != "true" {
		t.Fatalf("passive = %q, want true", result.Findings["passive"])
	}
	if strings.Contains(result.Findings["data_source"], "ipqualityscore") {
		t.Fatalf("data_source = %q, did not expect ipqualityscore", result.Findings["data_source"])
	}
}

func TestAbstractAPIResponseIsSharedThroughCache(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"valid": true,
			"type": "voip",
			"carrier": "Abstract VOIP",
			"country": {"code": "US", "name": "United States"}
		}`))
	}))
	defer server.Close()

	ctx := core.ContextWithResponseCache(context.Background(), core.NewResponseCache())
	number := mobileNumber()
	carrierModule := carrier.New(
		carrier.WithAPIKeys("", "abstract-key"),
		carrier.WithEndpoints("", server.URL),
		carrier.WithRateLimiter(core.NewRateLimiter(0)),
	)
	voipModule := New(
		WithAPIKeys("", "abstract-key"),
		WithEndpoints("", server.URL),
		WithRateLimiter(core.NewRateLimiter(0)),
	)

	if _, err := carrierModule.Run(ctx, number); err != nil {
		t.Fatalf("carrier run: %v", err)
	}
	result, err := voipModule.Run(ctx, number)
	if err != nil {
		t.Fatalf("voip run: %v", err)
	}

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("abstract calls = %d, want 1", got)
	}
	if !result.Data.(Result).IsVOIP {
		t.Fatal("IsVOIP = false, want true from cached AbstractAPI response")
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

func mobileNumber() *core.PhoneNumber {
	return &core.PhoneNumber{
		E164:           "+14155552671",
		CountryCode:    1,
		CountryAlpha2:  "US",
		NationalNumber: "4155552671",
		LineType:       core.LineTypeMobile,
		CarrierHint:    "Example Mobile",
		Timezone:       "America/Los_Angeles",
		Valid:          true,
	}
}
