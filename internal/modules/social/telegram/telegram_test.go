package telegram

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

func TestTelegramFoundWithUsernameAndPhoto(t *testing.T) {
	photo := writeTestPNG(t)
	module := New(
		WithCredentials("12345", "hash"),
		WithRateLimiter(core.NewRateLimiter(0)),
		WithClient(fakeClient{account: &core.MessengerAccount{
			Found:            true,
			DisplayName:      "Ada Lovelace",
			Username:         "@ada",
			Bio:              "math",
			LastSeenBucket:   "recently",
			AccountID:        "42",
			ProfilePhotoPath: photo,
		}}),
	)
	result, err := module.Run(context.Background(), &core.PhoneNumber{E164: "+14155552671"})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Findings["found"] != "true" || result.Findings["username"] != "@ada" {
		t.Fatalf("findings = %#v", result.Findings)
	}
	if result.Findings["profile_photo_phash"] == "" {
		t.Fatalf("profile_photo_phash is empty")
	}
}

func TestTelegramNotFound(t *testing.T) {
	module := New(WithCredentials("12345", "hash"), WithRateLimiter(core.NewRateLimiter(0)), WithClient(fakeClient{}))
	result, err := module.Run(context.Background(), &core.PhoneNumber{E164: "+14155552671"})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Findings["found"] != "false" {
		t.Fatalf("found = %q, want false", result.Findings["found"])
	}
}

func TestTelegramDryRunMissingCredentials(t *testing.T) {
	module := New(WithCredentials("", ""), WithClient(fakeClient{}))
	err := module.DryRun(context.Background(), &core.PhoneNumber{})
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("TELEGRAM_APP_ID")) {
		t.Fatalf("DryRun() error = %v, want setup instructions", err)
	}
}

type fakeClient struct {
	account *core.MessengerAccount
}

func (f fakeClient) Lookup(ctx context.Context, number *core.PhoneNumber) (*core.MessengerAccount, error) {
	if f.account == nil {
		return &core.MessengerAccount{Found: false}, nil
	}
	return f.account, nil
}

func (f fakeClient) Setup(ctx context.Context, stdin io.Reader, stdout io.Writer) error { return nil }

func writeTestPNG(t *testing.T) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x * 30), G: uint8(y * 30), B: 100, A: 255})
		}
	}
	path := filepath.Join(t.TempDir(), "photo.png")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create png: %v", err)
	}
	defer file.Close()
	if err := png.Encode(file, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return path
}
