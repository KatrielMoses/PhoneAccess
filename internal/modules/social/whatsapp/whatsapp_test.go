package whatsapp

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

func TestWhatsAppFound(t *testing.T) {
	module := New(WithRateLimiter(core.NewRateLimiter(0)), WithClient(fakeClient{
		hasSession: true,
		account: &core.MessengerAccount{
			Found:       true,
			DisplayName: "Grace",
			AboutBio:    "available",
		},
	}))
	if err := module.DryRun(context.Background(), &core.PhoneNumber{E164: "+14155552671"}); err != nil {
		t.Fatalf("DryRun() error = %v", err)
	}
	result, err := module.Run(context.Background(), &core.PhoneNumber{E164: "+14155552671"})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Findings["found"] != "true" || result.Findings["about_bio"] != "available" {
		t.Fatalf("findings = %#v", result.Findings)
	}
}

func TestWhatsAppNoSessionDryRunSkip(t *testing.T) {
	module := New(WithClient(fakeClient{}))
	err := module.DryRun(context.Background(), &core.PhoneNumber{})
	if err == nil || !strings.Contains(err.Error(), "whatsapp setup") || !strings.Contains(err.Error(), "personal WhatsApp account") {
		t.Fatalf("DryRun() error = %v, want setup and disclaimer", err)
	}
}

type fakeClient struct {
	hasSession bool
	account    *core.MessengerAccount
}

func (f fakeClient) Lookup(ctx context.Context, number *core.PhoneNumber) (*core.MessengerAccount, error) {
	return f.account, nil
}

func (f fakeClient) Setup(ctx context.Context, stdout io.Writer) error { return nil }
func (f fakeClient) HasSession() bool                                  { return f.hasSession }
