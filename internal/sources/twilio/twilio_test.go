package twilio

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type testHTTPClient struct {
	check  func(*http.Request)
	body   string
	status int
}

func (c testHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if c.check != nil {
		c.check(req)
	}
	if c.status == 0 {
		c.status = http.StatusOK
	}
	return &http.Response{
		StatusCode: c.status,
		Body:       io.NopCloser(strings.NewReader(c.body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}, nil
}

func TestTwilioBasicAuthAndFields(t *testing.T) {
	var gotReq *http.Request
	source := New(
		WithCredentials("AC123", "token123"),
		WithCallerNameEnabled(true),
		WithBaseURL("https://example.test/v2/PhoneNumbers"),
		WithHTTPClient(testHTTPClient{
			check: func(req *http.Request) {
				gotReq = req
			},
			body: `{"line_type_intelligence":{"carrier_name":"Example Carrier","type":"fixedVoip","mobile_country_code":"310","mobile_network_code":"260"},"caller_name":{"caller_name":"Jane Roe","caller_type":"consumer"}}`,
		}),
	)

	claims, err := source.Fetch(context.Background(), "+14155552671")
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if gotReq == nil {
		t.Fatal("expected request to be captured")
	}
	user, pass, ok := gotReq.BasicAuth()
	if !ok || user != "AC123" || pass != "token123" {
		t.Fatalf("BasicAuth = %q/%q ok=%v, want AC123/token123", user, pass, ok)
	}
	if fields := gotReq.URL.Query().Get("Fields"); fields != "line_type_intelligence,caller_name" {
		t.Fatalf("Fields = %q, want caller_name enabled", fields)
	}
	if len(claims) != 3 {
		t.Fatalf("claims = %d, want carrier + line type + caller name", len(claims))
	}
}

func TestTwilioCallerNameSuppressedWithoutFlag(t *testing.T) {
	var gotReq *http.Request
	source := New(
		WithCredentials("AC123", "token123"),
		WithBaseURL("https://example.test/v2/PhoneNumbers"),
		WithHTTPClient(testHTTPClient{
			check: func(req *http.Request) {
				gotReq = req
			},
			body: `{"line_type_intelligence":{"carrier_name":"Example Carrier","type":"mobile"}}`,
		}),
	)

	_, err := source.Fetch(context.Background(), "+14155552671")
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if gotReq == nil {
		t.Fatal("expected request to be captured")
	}
	if fields := gotReq.URL.Query().Get("Fields"); fields != "line_type_intelligence" {
		t.Fatalf("Fields = %q, want caller_name suppressed", fields)
	}
}

func TestTwilioDryRunMissingCredentials(t *testing.T) {
	source := New()
	if err := source.DryRun(context.Background(), "+14155552671"); err == nil {
		t.Fatal("DryRun() error = nil, want missing credentials")
	}
}
