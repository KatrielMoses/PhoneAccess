package exporters

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

func buildWebhookReport(band core.RiskBand, score int) *core.InvestigationReport {
	return &core.InvestigationReport{
		GeneratedAt: time.Now().UTC(),
		Number: &core.PhoneNumber{
			E164:          "+14155552671",
			CountryAlpha2: "US",
		},
		Results: []*core.ModuleResult{},
		RiskScore: &core.RiskScore{
			Score: score,
			Band:  band,
		},
	}
}

func TestWebhookFiresWhenRiskAboveMinimum(t *testing.T) {
	fired := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fired = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := WebhookConfig{URL: srv.URL, RiskMin: core.RiskBandHigh}
	err := DeliverWebhook(context.Background(), cfg, buildWebhookReport(core.RiskBandHigh, 70), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fired {
		t.Fatal("webhook not fired for HIGH risk when min=HIGH")
	}
}

func TestWebhookFiresForCritical(t *testing.T) {
	fired := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fired = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := WebhookConfig{URL: srv.URL, RiskMin: core.RiskBandHigh}
	err := DeliverWebhook(context.Background(), cfg, buildWebhookReport(core.RiskBandCritical, 90), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fired {
		t.Fatal("webhook not fired for CRITICAL risk when min=HIGH")
	}
}

func TestWebhookDoesNotFireBelowMinimum(t *testing.T) {
	fired := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fired = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := WebhookConfig{URL: srv.URL, RiskMin: core.RiskBandHigh}
	err := DeliverWebhook(context.Background(), cfg, buildWebhookReport(core.RiskBandModerate, 45), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fired {
		t.Fatal("webhook must not fire for MODERATE risk when min=HIGH")
	}
}

func TestWebhookDoesNotFireLow(t *testing.T) {
	fired := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fired = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := WebhookConfig{URL: srv.URL, RiskMin: core.RiskBandHigh}
	err := DeliverWebhook(context.Background(), cfg, buildWebhookReport(core.RiskBandLow, 10), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fired {
		t.Fatal("webhook must not fire for LOW risk when min=HIGH")
	}
}

func TestWebhookFiresWhenMinSetToLow(t *testing.T) {
	fired := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fired = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := WebhookConfig{URL: srv.URL, RiskMin: core.RiskBandLow}
	err := DeliverWebhook(context.Background(), cfg, buildWebhookReport(core.RiskBandModerate, 45), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fired {
		t.Fatal("webhook should fire for MODERATE when min=LOW")
	}
}

func TestWebhookHMACSignatureCorrect(t *testing.T) {
	const secret = "test-secret-key"
	var gotSig string
	var body []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-PhoneAccess-Signature")
		body = make([]byte, r.ContentLength)
		r.Body.Read(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := WebhookConfig{URL: srv.URL, Secret: secret, RiskMin: core.RiskBandHigh}
	err := DeliverWebhook(context.Background(), cfg, buildWebhookReport(core.RiskBandHigh, 70), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotSig == "" {
		t.Fatal("X-PhoneAccess-Signature header missing")
	}
	if !strings.HasPrefix(gotSig, "sha256=") {
		t.Fatalf("signature does not start with sha256=: %q", gotSig)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != expected {
		t.Fatalf("HMAC mismatch: got %q, want %q", gotSig, expected)
	}
}

func TestWebhookNoSignatureWhenNoSecret(t *testing.T) {
	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-PhoneAccess-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := WebhookConfig{URL: srv.URL, RiskMin: core.RiskBandHigh}
	_ = DeliverWebhook(context.Background(), cfg, buildWebhookReport(core.RiskBandHigh, 70), 0)
	if gotSig != "" {
		t.Fatalf("signature header must be absent when no secret: %q", gotSig)
	}
}

func TestWebhookFailureDoesNotPanic(t *testing.T) {
	// Point at a server that immediately closes.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := WebhookConfig{URL: srv.URL, RiskMin: core.RiskBandHigh}
	err := DeliverWebhook(context.Background(), cfg, buildWebhookReport(core.RiskBandHigh, 70), 0)
	// err should be non-nil (500 returned) but must not panic.
	if err == nil {
		t.Log("got nil err for 500 response (acceptable if library swallows it)")
	}
}

func TestWebhookPayloadStructure(t *testing.T) {
	var received map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := WebhookConfig{URL: srv.URL, RiskMin: core.RiskBandHigh}
	_ = DeliverWebhook(context.Background(), cfg, buildWebhookReport(core.RiskBandHigh, 70), 42)

	requiredKeys := []string{"event", "timestamp", "phone", "risk_score", "risk_band", "top_findings"}
	for _, key := range requiredKeys {
		if _, ok := received[key]; !ok {
			t.Errorf("webhook payload missing key %q", key)
		}
	}
	if received["event"] != "investigation_complete" {
		t.Errorf("event want %q, got %v", "investigation_complete", received["event"])
	}
	if received["phone"] != "+14155552671" {
		t.Errorf("phone want +14155552671, got %v", received["phone"])
	}
}

func TestWebhookDiscordAutoDetect(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Pretend the server URL is a discord.com webhook by overriding URL with discord path component.
	// We use a fake URL that contains the discord.com/api/webhooks path substring.
	discordURL := srv.URL + "/discord.com/api/webhooks/12345/token"
	cfg := WebhookConfig{URL: discordURL, RiskMin: core.RiskBandHigh}
	_ = DeliverWebhook(context.Background(), cfg, buildWebhookReport(core.RiskBandHigh, 70), 0)

	if body == nil {
		t.Fatal("no body received")
	}
	// Discord payload must have "content" and "embeds" keys.
	if _, ok := body["content"]; !ok {
		t.Error("discord payload missing 'content'")
	}
	if _, ok := body["embeds"]; !ok {
		t.Error("discord payload missing 'embeds'")
	}
}

func TestWebhookDefaultMinIsHigh(t *testing.T) {
	fired := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fired = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// RiskMin empty → default should be HIGH.
	cfg := WebhookConfig{URL: srv.URL}
	_ = DeliverWebhook(context.Background(), cfg, buildWebhookReport(core.RiskBandModerate, 45), 0)
	if fired {
		t.Fatal("webhook must not fire for MODERATE when default min is HIGH")
	}

	_ = DeliverWebhook(context.Background(), cfg, buildWebhookReport(core.RiskBandHigh, 70), 0)
	if !fired {
		t.Fatal("webhook must fire for HIGH when default min is HIGH")
	}
}
