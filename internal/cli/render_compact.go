package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

const (
	ansiReset    = "\033[0m"
	ansiGreen    = "\033[32m"
	ansiYellow   = "\033[33m"
	ansiRed      = "\033[31m"
)

func compactRiskColor(band core.RiskBand) string {
	switch band {
	case core.RiskBandLow:
		return ansiGreen
	case core.RiskBandModerate:
		return ansiYellow
	case core.RiskBandHigh, core.RiskBandCritical:
		return ansiRed
	default:
		return ""
	}
}

// CompactRenderer renders a ≤6-line summary for fast triage and field use.
type CompactRenderer struct{}

func NewCompactRenderer() *CompactRenderer { return &CompactRenderer{} }

func (r *CompactRenderer) Render(report *core.InvestigationReport) string {
	lines := make([]string, 0, 6)

	lines = append(lines, compactLine1(report))

	if l := compactLine2(report); l != "" {
		lines = append(lines, l)
	}
	if l := compactLine3(report); l != "" {
		lines = append(lines, l)
	}
	if l := compactLine4(report); l != "" {
		lines = append(lines, l)
	}
	if l := compactLine5(report); l != "" {
		lines = append(lines, l)
	}

	// Hard cap at 6 lines (line 1 is always present).
	if len(lines) > 6 {
		lines = lines[:6]
	}
	return strings.Join(lines, "\n") + "\n"
}

func compactLine1(report *core.InvestigationReport) string {
	if report == nil || report.Number == nil {
		return "(no number)"
	}
	n := report.Number

	carrier := strings.TrimSpace(n.CarrierHint)
	if f := moduleFindings(report, "carrier"); f != nil {
		if v := strings.TrimSpace(f["carrier"]); v != "" {
			carrier = v
		}
	}

	lineType := strings.TrimSpace(string(n.LineType))
	country := strings.TrimSpace(n.CountryAlpha2)
	region := strings.TrimSpace(n.RegionDescription)

	detail := []string{}
	if country != "" {
		detail = append(detail, country)
	}
	if carrier != "" {
		detail = append(detail, carrier)
	}
	if lineType != "" && lineType != "unknown" {
		detail = append(detail, strings.Title(lineType))
	}
	if region != "" {
		detail = append(detail, region)
	}

	if len(detail) == 0 {
		return n.E164
	}
	return n.E164 + "  " + strings.Join(detail, " · ")
}

func compactLine2(report *core.InvestigationReport) string {
	risk := report.RiskScore
	if risk == nil {
		risk = core.ScoreRisk(report)
	}

	color := compactRiskColor(risk.Band)
	riskStr := fmt.Sprintf("RISK: %s%d/100 %s%s", color, risk.Score, string(risk.Band), ansiReset)
	parts := []string{riskStr}

	if f := moduleFindings(report, "spam"); f != nil {
		reports := strings.TrimSpace(f["total_reports"])
		if reports == "" {
			reports = "0"
		}
		parts = append(parts, "Spam: "+reports+" reports")
	}

	if f := moduleFindings(report, "breach"); f != nil {
		if count := strings.TrimSpace(f["breach_count"]); count != "" {
			parts = append(parts, "Breaches: "+count)
		}
	}

	if f := moduleFindings(report, "enumerator"); f != nil {
		hits := strings.TrimSpace(f["hit_count"])
		total := strings.TrimSpace(f["total_services"])
		if hits != "" && total != "" {
			parts = append(parts, fmt.Sprintf("Services: %s/%s", hits, total))
		}
	}

	return strings.Join(parts, "  |  ")
}

func compactLine3(report *core.InvestigationReport) string {
	parts := []string{}

	if rec := identityRecord(report); rec != nil {
		if len(rec.Names) > 0 {
			top := rec.Names[0]
			src := ""
			if len(top.Sources) > 0 {
				src = top.Sources[0].Name
			}
			parts = append(parts, fmt.Sprintf("Identity: %s (%.2f, %s)", top.DisplayValue, top.Confidence, src))
		}
		if len(rec.Emails) > 0 {
			parts = append(parts, "Email pivot: "+rec.Emails[0].DisplayValue)
		}
	}

	// Fall back to identity graph email pivots.
	if len(parts) == 0 && report.IdentityGraph != nil {
		for _, p := range report.IdentityGraph.PivotPoints {
			if strings.ToLower(p.Type) == "email" && p.Value != "" {
				parts = append(parts, "Email pivot: "+p.Value)
				break
			}
		}
	}

	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "  |  ")
}

func compactLine4(report *core.InvestigationReport) string {
	if report.Messenger == nil {
		return ""
	}

	icon := func(label string, acct *core.MessengerAccount) string {
		if acct != nil && acct.Found {
			return "✓" + label
		}
		return "—" + label
	}

	parts := []string{
		icon("WhatsApp", report.Messenger.WhatsApp),
		icon("Telegram", report.Messenger.Telegram),
		icon("Signal", report.Messenger.Signal),
	}
	return "Messenger: " + strings.Join(parts, "  ")
}

func compactLine5(report *core.InvestigationReport) string {
	if report.Timeline == nil {
		return ""
	}
	first := strings.TrimSpace(report.Timeline.FirstSeen)
	last := strings.TrimSpace(report.Timeline.MostRecent)
	if first == "" && last == "" {
		return ""
	}

	parts := []string{}
	if first != "" {
		parts = append(parts, "first seen "+first)
	}
	if last != "" {
		parts = append(parts, "last seen "+last)
	}
	return "Timeline: " + strings.Join(parts, "  |  ")
}

// FieldRenderer renders a single pipe-delimited line safe for piping and grep.
// Fields: e164|risk_band|risk_score|carrier|line_type|country|breach_count|service_hits|top_name|messengers
type FieldRenderer struct{}

func NewFieldRenderer() *FieldRenderer { return &FieldRenderer{} }

func (r *FieldRenderer) Render(report *core.InvestigationReport) string {
	return fieldLine(report) + "\n"
}

func fieldLine(report *core.InvestigationReport) string {
	if report == nil {
		return "||||||||||"
	}

	e164, country, carrier, lineType := "", "", "", ""
	if report.Number != nil {
		e164 = report.Number.E164
		country = report.Number.CountryAlpha2
		lineType = string(report.Number.LineType)
		carrier = strings.TrimSpace(report.Number.CarrierHint)
	}
	if f := moduleFindings(report, "carrier"); f != nil {
		if v := strings.TrimSpace(f["carrier"]); v != "" {
			carrier = v
		}
	}

	risk := report.RiskScore
	if risk == nil {
		risk = core.ScoreRisk(report)
	}
	riskBand := string(risk.Band)
	riskScore := strconv.Itoa(risk.Score)

	breachCount := ""
	if f := moduleFindings(report, "breach"); f != nil {
		breachCount = strings.TrimSpace(f["breach_count"])
	}

	serviceHits := ""
	if f := moduleFindings(report, "enumerator"); f != nil {
		serviceHits = strings.TrimSpace(f["hit_count"])
	}

	topName := ""
	if rec := identityRecord(report); rec != nil && len(rec.Names) > 0 {
		topName = rec.Names[0].DisplayValue
	}

	msgrs := []string{}
	if report.Messenger != nil {
		if report.Messenger.WhatsApp != nil && report.Messenger.WhatsApp.Found {
			msgrs = append(msgrs, "WhatsApp")
		}
		if report.Messenger.Telegram != nil && report.Messenger.Telegram.Found {
			msgrs = append(msgrs, "Telegram")
		}
		if report.Messenger.Signal != nil && report.Messenger.Signal.Found {
			msgrs = append(msgrs, "Signal")
		}
	}

	return strings.Join([]string{
		e164,
		riskBand,
		riskScore,
		carrier,
		lineType,
		country,
		breachCount,
		serviceHits,
		topName,
		strings.Join(msgrs, ","),
	}, "|")
}
