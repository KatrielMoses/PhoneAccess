package nigeriaphonebook

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

func TestNigeriaPhoneBookRunsOnlyForNigeria(t *testing.T) {
	source := New(WithHTTPClient(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("<html><title>Jane Doe - Nigeria Phone Book</title></html>")),
			Header:     http.Header{},
		}, nil
	})), WithRateLimiter(core.NewRateLimiter(0)))

	if err := source.DryRun(context.Background(), "+14155552671"); err == nil {
		t.Fatal("DryRun() for US number = nil, want skip")
	}
	if err := source.DryRun(context.Background(), "+2348012345678"); err != nil {
		t.Fatalf("DryRun() for NG number error = %v", err)
	}
	claims, err := source.Fetch(context.Background(), "+2348012345678")
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if len(claims) != 1 || claims[0].Value != "Jane Doe" {
		t.Fatalf("claims = %#v", claims)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }
