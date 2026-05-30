package exporters

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

// WebhookConfig holds delivery configuration for a single webhook endpoint.
type WebhookConfig struct {
	URL     string
	Secret  string       // HMAC-SHA256 signing secret (optional)
	RiskMin core.RiskBand // minimum band to fire (default: HIGH)
}

// WebhookPayload is the JSON body posted to non-Discord endpoints.
type WebhookPayload struct {
	Event       string          `json:"event"`
	Timestamp   string          `json:"timestamp"`
	Phone       string          `json:"phone"`
	RiskScore   int             `json:"risk_score"`
	RiskBand    string          `json:"risk_band"`
	TopFindings WebhookFindings `json:"top_findings"`
	CaseID      int64           `json:"case_id,omitempty"`
}

// WebhookFindings holds the key findings embedded in a webhook payload.
type WebhookFindings struct {
	Carrier     string   `json:"carrier"`
	BreachCount int      `json:"breach_count"`
	ServiceHits int      `json:"service_hits"`
	TopName     string   `json:"top_name,omitempty"`
	Messengers  []string `json:"messengers"`
}

func riskBandLevel(band core.RiskBand) int {
	switch band {
	case core.RiskBandLow:
		return 0
	case core.RiskBandModerate:
		return 1
	case core.RiskBandHigh:
		return 2
	case core.RiskBandCritical:
		return 3
	default:
		return -1
	}
}

// DeliverWebhook sends the report to the configured webhook URL.
// It is best-effort: the investigation never fails due to webhook errors.
// Returns a non-nil error only when the caller wants to log a warning.
func DeliverWebhook(ctx context.Context, cfg WebhookConfig, report *core.InvestigationReport, caseID int64) error {
	if cfg.URL == "" || report == nil {
		return nil
	}

	risk := report.RiskScore
	if risk == nil {
		risk = core.ScoreRisk(report)
	}

	minBand := cfg.RiskMin
	if minBand == "" {
		minBand = core.RiskBandHigh
	}
	if riskBandLevel(risk.Band) < riskBandLevel(minBand) {
		return nil // below threshold — do not fire
	}

	phone := ""
	if report.Number != nil {
		phone = report.Number.E164
		if phone == "" {
			phone = report.Number.RawInput
		}
	}

	carrier := ""
	if f := webhookModuleFindings(report, "carrier"); f != nil {
		carrier = strings.TrimSpace(f["carrier"])
	}

	breachCount := 0
	if f := webhookModuleFindings(report, "breach"); f != nil {
		fmt.Sscan(f["breach_count"], &breachCount)
	}

	serviceHits := 0
	if f := webhookModuleFindings(report, "enumerator"); f != nil {
		fmt.Sscan(f["hit_count"], &serviceHits)
	}

	topName := ""
	msgrs := []string{}
	if report.Messenger != nil {
		if report.Messenger.WhatsApp != nil && report.Messenger.WhatsApp.Found {
			msgrs = append(msgrs, "WhatsApp")
			if report.Messenger.WhatsApp.DisplayName != "" && topName == "" {
				topName = report.Messenger.WhatsApp.DisplayName
			}
		}
		if report.Messenger.Telegram != nil && report.Messenger.Telegram.Found {
			msgrs = append(msgrs, "Telegram")
			if report.Messenger.Telegram.DisplayName != "" && topName == "" {
				topName = report.Messenger.Telegram.DisplayName
			}
		}
		if report.Messenger.Signal != nil && report.Messenger.Signal.Found {
			msgrs = append(msgrs, "Signal")
		}
	}

	payload := WebhookPayload{
		Event:     "investigation_complete",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Phone:     phone,
		RiskScore: risk.Score,
		RiskBand:  string(risk.Band),
		TopFindings: WebhookFindings{
			Carrier:     carrier,
			BreachCount: breachCount,
			ServiceHits: serviceHits,
			TopName:     topName,
			Messengers:  msgrs,
		},
		CaseID: caseID,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	// Auto-detect Discord and reformat payload.
	if strings.Contains(cfg.URL, "discord.com/api/webhooks") {
		body, err = buildDiscordPayload(payload, risk)
		if err != nil {
			return fmt.Errorf("build discord payload: %w", err)
		}
	}

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "PhoneAccess-Webhook/1.0")

	if cfg.Secret != "" {
		mac := hmac.New(sha256.New, []byte(cfg.Secret))
		mac.Write(body)
		req.Header.Set("X-PhoneAccess-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook delivery failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func webhookModuleFindings(report *core.InvestigationReport, name string) map[string]string {
	for _, r := range report.Results {
		if r != nil && r.ModuleName == name {
			return r.Findings
		}
	}
	return nil
}

type discordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type discordEmbed struct {
	Title  string              `json:"title"`
	Color  int                 `json:"color"`
	Fields []discordEmbedField `json:"fields"`
}

func discordColor(band core.RiskBand) int {
	switch band {
	case core.RiskBandCritical:
		return 10038562 // dark red
	case core.RiskBandHigh:
		return 15158332 // red
	case core.RiskBandModerate:
		return 16776960 // yellow
	default:
		return 65280 // green
	}
}

func buildDiscordPayload(p WebhookPayload, risk *core.RiskScore) ([]byte, error) {
	title := fmt.Sprintf("%s — %s (%d/100)", p.Phone, p.RiskBand, p.RiskScore)

	fields := []discordEmbedField{
		{Name: "Risk Band", Value: p.RiskBand, Inline: true},
	}
	if p.TopFindings.Carrier != "" {
		fields = append(fields, discordEmbedField{Name: "Carrier", Value: p.TopFindings.Carrier, Inline: true})
	}
	fields = append(fields,
		discordEmbedField{Name: "Breaches", Value: fmt.Sprintf("%d", p.TopFindings.BreachCount), Inline: true},
		discordEmbedField{Name: "Services", Value: fmt.Sprintf("%d", p.TopFindings.ServiceHits), Inline: true},
	)
	if p.TopFindings.TopName != "" {
		fields = append(fields, discordEmbedField{Name: "Identity", Value: p.TopFindings.TopName, Inline: true})
	}
	if len(p.TopFindings.Messengers) > 0 {
		fields = append(fields, discordEmbedField{
			Name:   "Messengers",
			Value:  strings.Join(p.TopFindings.Messengers, ", "),
			Inline: true,
		})
	}

	out := map[string]any{
		"content": "⚠ PhoneAccess Alert",
		"embeds": []discordEmbed{
			{Title: title, Color: discordColor(risk.Band), Fields: fields},
		},
	}
	return json.Marshal(out)
}
