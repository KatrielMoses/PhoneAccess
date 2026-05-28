package cli

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
	"github.com/KatrielMoses/PhoneAccess/internal/correlator"
	publicrecords "github.com/KatrielMoses/PhoneAccess/internal/modules/publicrecords"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/search"
	"github.com/charmbracelet/lipgloss"
)

type RenderBlock interface {
	Render(report *core.InvestigationReport) string
}

type TerminalRenderer struct {
	blocks []RenderBlock
}

func NewTerminalRenderer() *TerminalRenderer {
	return &TerminalRenderer{
		blocks: []RenderBlock{
			NumberIntelligenceBlock{},
			CarrierIntelligenceBlock{},
			VOIPIntelligenceBlock{},
			GeographicIntelligenceBlock{},
			SpamReputationBlock{},
			BreachIntelligenceBlock{},
			PublicRecordsBlock{},
			ReverseLookupBlock{},
			TimelineBlock{},
			MessengerPresenceBlock{},
			ServiceEnumerationBlock{},
			FinancialFootprintBlock{},
			IdentityGraphBlock{},
			PivotChainBlock{},
			IdentityRecordBlock{},
			RiskScoreBlock{},
		},
	}
}

func (r *TerminalRenderer) Render(report *core.InvestigationReport) string {
	var parts []string
	parts = append(parts, banner())
	for _, block := range r.blocks {
		parts = append(parts, block.Render(report))
	}
	return strings.Join(parts, "\n\n") + "\n"
}

type NumberIntelligenceBlock struct{}

func (NumberIntelligenceBlock) Render(report *core.InvestigationReport) string {
	number := report.Number
	title := sectionTitleStyle.Render("NUMBER INTELLIGENCE")
	rows := []string{
		row("Raw input", number.RawInput),
		row("Normalized", number.E164),
		row("Valid", fmt.Sprintf("%t", number.Valid)),
		row("Country", fmt.Sprintf("+%d (%s)", number.CountryCode, number.CountryAlpha2)),
		row("National number", number.NationalNumber),
		row("Region", number.RegionDescription),
		row("Line type", string(number.LineType)),
		row("Carrier hint", empty(number.CarrierHint)),
		row("Timezone", number.Timezone),
	}

	return lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(rows, "\n"))
}

type CarrierIntelligenceBlock struct{}

func (CarrierIntelligenceBlock) Render(report *core.InvestigationReport) string {
	findings := moduleFindings(report, "carrier")
	title := sectionTitleStyle.Render("CARRIER INTELLIGENCE")
	if len(findings) == 0 {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "not available"))
	}

	rows := []string{
		row("Carrier", withConfidence(empty(findings["carrier"]), findings["carrier_confidence"])),
		row("Line type", withConfidence(empty(findings["line_type"]), findings["line_type_confidence"])),
		row("VOIP status", voipStatus(findings)),
		row("Timezone", withConfidence(empty(findings["timezone"]), findings["timezone_confidence"])),
		row("Data source", empty(findings["data_source"])),
		row("Confidence", confidenceSummary(findings)),
	}

	return lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(rows, "\n"))
}

type VOIPIntelligenceBlock struct{}

func (VOIPIntelligenceBlock) Render(report *core.InvestigationReport) string {
	findings := moduleFindings(report, "voip")
	title := sectionTitleStyle.Render("VOIP INTELLIGENCE")
	if len(findings) == 0 {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "not available"))
	}

	status := "not detected"
	if strings.EqualFold(findings["is_voip"], "true") {
		status = "detected"
	}
	rows := []string{
		row("VOIP status", withConfidence(status, findings["confidence"])),
		row("Provider", empty(findings["provider"])),
		row("Prepaid", empty(findings["is_prepaid"])),
		row("Data source", empty(findings["data_source"])),
	}
	if signals := splitSnippets(findings["risk_signals"], 6); len(signals) > 0 {
		rows = append(rows, quoteBlock(signals))
	}

	return lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(rows, "\n"))
}

type GeographicIntelligenceBlock struct{}

func (GeographicIntelligenceBlock) Render(report *core.InvestigationReport) string {
	findings := moduleFindings(report, "geo")
	title := sectionTitleStyle.Render("GEOGRAPHIC INTELLIGENCE")
	if len(findings) == 0 {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "not available"))
	}

	risk := "not flagged"
	if strings.EqualFold(findings["regional_risk_flag"], "true") {
		risk = "flagged: " + empty(findings["regional_risk_region"])
	}
	rows := []string{
		row("Area code origin", empty(findings["area_code_origin"])),
		row("Split/overlay", empty(findings["area_code_split_history"])),
		row("Ported hint", fmt.Sprintf("%s - %s", empty(findings["likely_ported"]), empty(findings["ported_reason"]))),
		row("Local time", fmt.Sprintf("%s (%s)", empty(findings["local_time"]), empty(findings["utc_offset"]))),
		row("Business hours", empty(findings["business_hours"])),
		row("Regional risk", risk),
	}
	if strings.EqualFold(findings["regional_risk_flag"], "true") {
		rows = append(rows, quoteBlock([]string{empty(findings["regional_risk_basis"])}))
	}

	return lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(rows, "\n"))
}

type SpamReputationBlock struct{}

func (SpamReputationBlock) Render(report *core.InvestigationReport) string {
	findings := moduleFindings(report, "spam")
	title := sectionTitleStyle.Render("SPAM & REPUTATION")
	if len(findings) == 0 {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "not available"))
	}
	if strings.EqualFold(findings["skipped"], "true") {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "skipped"), row("Note", empty(findings["note"])))
	}

	score, _ := strconv.Atoi(findings["spam_score"])
	risk := riskStyle(findings["risk"], score).Render(empty(findings["risk"]))
	sourcesHit := empty(findings["sources_with_hits"])
	if sourcesHit == "unknown" {
		sourcesHit = "none"
	}
	rows := []string{
		row("Overall risk", fmt.Sprintf("%s (%d/100)", risk, score)),
		row("Reports", empty(findings["total_reports"])),
		row("Sources hit", sourcesHit),
		row("Caller type", empty(findings["caller_type"])),
	}
	if tags := strings.TrimSpace(findings["truecaller_tags"]); tags != "" {
		rows = append(rows, row("Truecaller tags", tags))
	}
	if recent := strings.TrimSpace(findings["most_recent_report"]); recent != "" {
		rows = append(rows, row("Recent report", recent))
	}

	snippets := splitSnippets(findings["report_snippets"], 3)
	if len(snippets) > 0 {
		rows = append(rows, quoteBlock(snippets))
	}

	return lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(rows, "\n"))
}

type BreachIntelligenceBlock struct{}

func (BreachIntelligenceBlock) Render(report *core.InvestigationReport) string {
	findings := moduleFindings(report, "breach")
	title := sectionTitleStyle.Render("BREACH INTELLIGENCE")
	if len(findings) == 0 {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "not available"))
	}
	if strings.EqualFold(findings["skipped"], "true") {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "skipped"), row("Note", empty(findings["note"])))
	}

	breachCount, _ := strconv.Atoi(findings["breach_count"])
	stealerCount, _ := strconv.Atoi(findings["stealer_count"])
	machineCount, _ := strconv.Atoi(findings["compromised_machines"])
	hit := strings.EqualFold(findings["found"], "true") || breachCount > 0 || stealerCount > 0
	statusStyle := cleanStyle
	if hit {
		statusStyle = breachHitStyle
	}

	rows := []string{
		row("Summary", statusStyle.Render(fmt.Sprintf("Breaches: %d | Stealer logs: %d", breachCount, stealerCount))),
	}

	breaches := splitSnippets(findings["breaches"], 20)
	for _, breach := range breaches {
		rows = append(rows, breachHitStyle.Render("\u2713 "+breach))
	}
	if stealerCount > 0 {
		detail := fmt.Sprintf("! Infostealer logs associated with this number: %d", stealerCount)
		if machineCount > 0 {
			detail += fmt.Sprintf(" across %d compromised machines", machineCount)
		}
		if strings.EqualFold(findings["credentials_found"], "true") {
			detail += " with credentials present"
		}
		rows = append(rows, breachHitStyle.Render(detail))
	}
	if !hit {
		rows = append(rows, cleanStyle.Render("\u2713 No public breach or stealer-log hits found."))
	}

	return lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(rows, "\n"))
}

type PublicRecordsBlock struct{}

func (PublicRecordsBlock) Render(report *core.InvestigationReport) string {
	title := sectionTitleStyle.Render("PUBLIC RECORDS")
	if rawResult := moduleResult(report, "public_records"); rawResult != nil && rawResult.Status == core.ModuleStatusGated {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "gated — use --active to enable"))
	}
	result := publicRecordsResult(report)
	if result == nil {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "not available"))
	}
	if result.Skipped {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "skipped"), row("Note", empty(result.Note)))
	}

	lines := []string{}
	renderLine := func(label string, status string, details []string) {
		prefix := "—"
		switch {
		case strings.HasPrefix(strings.ToLower(status), "error"):
			prefix = "✗"
		case len(details) > 0:
			prefix = "✓"
		case strings.EqualFold(status, "hit"):
			prefix = "✓"
		}
		heading := fmt.Sprintf("%s %s", prefix, label)
		if strings.TrimSpace(status) != "" && status != "hit" {
			heading += " - " + status
		}
		lines = append(lines, row(label, heading))
		for _, detail := range details {
			lines = append(lines, valueStyle.Render("  - "+detail))
		}
	}

	renderLine("SEC EDGAR", result.SourceStatuses["SEC EDGAR"], formatEdgarLines(result.EdgarHits))
	renderLine("OpenCorporates", result.SourceStatuses["OpenCorporates"], formatOfficerLines(result.OpencorpHits))
	renderLine("Companies House", result.SourceStatuses["Companies House"], formatCompaniesHouseLines(result.CompaniesHouseHits))
	renderLine("PACER", result.SourceStatuses["PACER"], formatPacerLines(result.PacerHits))
	renderLine("Licenses", result.SourceStatuses["Licenses"], formatLicenseLines(result.LicenseHits))
	renderLine("Property hints", result.SourceStatuses["Property hints"], formatSearchHitLines(result.PropertyHints))

	if len(result.SourcesWithHits) == 0 {
		lines = append(lines, cleanStyle.Render("✓ No public-record hits found."))
	}

	return lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(lines, "\n"))
}

type ReverseLookupBlock struct{}

func (ReverseLookupBlock) Render(report *core.InvestigationReport) string {
	findings := moduleFindings(report, "reverse")
	title := sectionTitleStyle.Render("REVERSE LOOKUP")
	if len(findings) == 0 {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "not available"))
	}
	if strings.EqualFold(findings["skipped"], "true") {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "skipped"), row("Note", empty(findings["note"])))
	}

	sources := empty(findings["sources_with_hits"])
	if sources == "unknown" {
		sources = "none"
	}
	rows := []string{
		row("Name hint", withConfidence(empty(findings["name_hint"]), findings["name_confidence"])),
		row("Location hint", empty(findings["location_hint"])),
		row("Sources hit", sources),
		row("Sources checked", empty(findings["sources_checked"])),
	}
	if hits := splitSnippets(findings["raw_hits"], 4); len(hits) > 0 {
		rows = append(rows, quoteBlock(hits))
	}

	return lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(rows, "\n"))
}

type TimelineBlock struct{}

func (TimelineBlock) Render(report *core.InvestigationReport) string {
	title := sectionTitleStyle.Render("EXPOSURE TIMELINE")
	if report == nil || report.Timeline == nil || len(report.Timeline.Events) == 0 {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "no dated artifacts collected"))
	}

	lines := []string{
		row("First seen", empty(report.Timeline.FirstSeen)),
		row("Most recent", empty(report.Timeline.MostRecent)),
	}
	for _, event := range report.Timeline.Events {
		date := empty(event.Date)
		source := empty(event.Source)
		eventType := empty(event.EventType)
		description := empty(event.Description)
		confidence := empty(event.Confidence)
		line := fmt.Sprintf("%s | %s | %s | %s", date, source, eventType, description)
		if confidence != "unknown" {
			line += " (" + confidence + ")"
		}
		lines = append(lines, valueStyle.Render("- "+line))
	}
	return lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(lines, "\n"))
}

type MessengerPresenceBlock struct{}

func (MessengerPresenceBlock) Render(report *core.InvestigationReport) string {
	title := sectionTitleStyle.Render("MESSENGER PRESENCE")
	lines := []string{}
	add := func(label string, findings map[string]string) {
		if len(findings) == 0 {
			lines = append(lines, row(label, "not available"))
			return
		}
		if strings.EqualFold(findings["gated"], "true") {
			lines = append(lines, row(label, "gated — use --active to enable"))
			return
		}
		if strings.EqualFold(findings["skipped"], "true") {
			lines = append(lines, row(label, "skipped - "+empty(cliFirstNonEmpty(findings["reason"], findings["note"]))))
			return
		}
		status := "not found"
		if strings.EqualFold(findings["found"], "true") {
			status = "found"
		}
		parts := []string{status}
		if name := strings.TrimSpace(findings["display_name"]); name != "" {
			parts = append(parts, name)
		}
		if username := strings.TrimSpace(findings["username"]); username != "" {
			parts = append(parts, username)
		}
		if lastSeen := strings.TrimSpace(findings["last_seen_bucket"]); lastSeen != "" {
			parts = append(parts, "last seen: "+lastSeen)
		}
		if photo := strings.TrimSpace(findings["profile_photo_path"]); photo != "" {
			parts = append(parts, "photo: "+photo)
		}
		lines = append(lines, row(label, strings.Join(parts, " | ")))
	}
	add("Telegram", moduleFindings(report, "telegram"))
	add("WhatsApp", moduleFindings(report, "whatsapp"))
	return lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(lines, "\n"))
}

type ServiceEnumerationBlock struct{}

func (ServiceEnumerationBlock) Render(report *core.InvestigationReport) string {
	findings := moduleFindings(report, "enumerator")
	title := sectionTitleStyle.Render("SERVICE ENUMERATION")
	if len(findings) == 0 {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "not available"))
	}
	if strings.EqualFold(findings["gated"], "true") {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "gated — use --active to enable"))
	}
	if strings.EqualFold(findings["skipped"], "true") {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "skipped"), row("Note", empty(findings["note"])))
	}

	hitCount, _ := strconv.Atoi(findings["hit_count"])
	catsHit, _ := strconv.Atoi(findings["categories_hit"])
	total, _ := strconv.Atoi(findings["total_services"])

	statusStyle := cleanStyle
	if hitCount > 0 {
		statusStyle = breachHitStyle
	}

	rows := []string{
		row("Summary", statusStyle.Render(fmt.Sprintf("Found on %d/%d services across %d categories", hitCount, total, catsHit))),
		row("Categories", empty(findings["category_breakdown"])),
	}

	hits := splitSnippets(findings["hits"], 200)
	for _, hit := range hits {
		if strings.HasPrefix(hit, "[") && strings.HasSuffix(hit, "]") {
			rows = append(rows, "")
			rows = append(rows, labelStyle.Render(strings.ToUpper(strings.Trim(hit, "[]"))))
		} else {
			rows = append(rows, valueStyle.Render("  \u2713 "+hit))
		}
	}

	if names := strings.TrimSpace(findings["discovered_names"]); names != "" && names != "unknown" {
		rows = append(rows, row("Names found", names))
	}
	if usernames := strings.TrimSpace(findings["discovered_usernames"]); usernames != "" && usernames != "unknown" {
		rows = append(rows, row("Usernames found", usernames))
	}

	if hitCount == 0 {
		rows = append(rows, cleanStyle.Render("\u2713 No service registrations found for this number."))
	}

	return lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(rows, "\n"))
}

type FinancialFootprintBlock struct{}

func (FinancialFootprintBlock) Render(report *core.InvestigationReport) string {
	findings := moduleFindings(report, "finance")
	title := sectionTitleStyle.Render("FINANCIAL FOOTPRINT")
	if len(findings) == 0 {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "not available"))
	}
	if strings.EqualFold(findings["gated"], "true") {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "gated — use --active to enable"))
	}
	if strings.EqualFold(findings["skipped"], "true") {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "skipped"), row("Note", empty(findings["note"])))
	}

	hitCount, _ := strconv.Atoi(findings["hit_count"])
	checked, _ := strconv.Atoi(findings["checked"])

	summary := fmt.Sprintf("Found on %d/%d services", hitCount, checked)
	summaryStyle := cleanStyle
	if hitCount > 0 {
		summaryStyle = breachHitStyle
	}

	venmoName := strings.TrimSpace(findings["venmo_display_name"])
	venmoUser := strings.TrimSpace(findings["venmo_username"])
	venmoPrivacy := strings.TrimSpace(findings["venmo_privacy"])

	rows := []string{
		row("Summary", summaryStyle.Render(summary)),
	}

	if venmoName != "" || venmoUser != "" {
		venmoLine := "Venmo"
		if venmoName != "" {
			venmoLine += " " + venmoName
		}
		if venmoUser != "" {
			venmoLine += " (@" + venmoUser + ")"
		}
		if venmoPrivacy == "private" {
			venmoLine += " [private]"
		}
		rows = append(rows, breachHitStyle.Render("- "+venmoLine))
	}

	hits := splitSnippets(findings["service_hits"], 50)
	for _, hit := range hits {
		if strings.HasPrefix(hit, "Venmo") {
			continue
		}
		rows = append(rows, valueStyle.Render("- "+hit))
	}

	if hitCount == 0 {
		rows = append(rows, cleanStyle.Render("\u2713 No financial platform registrations found."))
	}

	return lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(rows, "\n"))
}

type IdentityGraphBlock struct{}

func (IdentityGraphBlock) Render(report *core.InvestigationReport) string {
	title := sectionTitleStyle.Render("IDENTITY GRAPH")
	if report.IdentityGraph == nil || len(report.IdentityGraph.PivotPoints) == 0 {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Pivots", "none discovered"))
	}

	lines := make([]string, 0, len(report.IdentityGraph.PivotPoints)+2)
	for _, pivot := range report.IdentityGraph.PivotPoints {
		modules := strings.Join(pivot.Modules, ", ")
		lines = append(lines, valueStyle.Render(fmt.Sprintf("- %s: %s %s %s (%s)", pivot.Type, pivot.Value, confidenceIcon(pivot.Confidence), pivot.Confidence, modules)))
	}
	if len(report.IdentityGraph.SuggestedCommands) > 0 {
		lines = append(lines, "")
		lines = append(lines, followupStyle.Render(strings.Join(report.IdentityGraph.SuggestedCommands, "\n")))
	}

	return lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(lines, "\n"))
}

type PivotChainBlock struct{}

func (PivotChainBlock) Render(report *core.InvestigationReport) string {
	title := sectionTitleStyle.Render("PIVOT CHAIN")
	if report == nil || report.PivotChain == nil {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "auto-pivot disabled or no pivots expanded"))
	}

	lines := pivotChainLines(report.PivotChain, 0)
	if len(lines) == 0 {
		lines = append(lines, row("Status", "no pivot chain entries"))
	}
	return lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(lines, "\n"))
}

func pivotChainLines(node *core.PivotChainNode, depth int) []string {
	if node == nil {
		return nil
	}

	lines := []string{}
	indent := strings.Repeat("  ", depth)
	label := strings.ToUpper(strings.TrimSpace(node.Type))
	value := empty(node.Value)
	line := fmt.Sprintf("%s%s: %s", indent, label, value)
	if strings.TrimSpace(node.Label) != "" {
		line += " - " + node.Label
	}
	if strings.TrimSpace(node.URL) != "" {
		line += " <" + node.URL + ">"
	}
	if node.Type != "phone" && node.ConfidenceLabel != "" {
		line += fmt.Sprintf(" (%.2f %s)", node.Confidence, node.ConfidenceLabel)
	}
	lines = append(lines, valueStyle.Render(line))
	for _, child := range node.Children {
		lines = append(lines, pivotChainLines(child, depth+1)...)
	}
	return lines
}

type IdentityRecordBlock struct{}

func (IdentityRecordBlock) Render(report *core.InvestigationReport) string {
	title := sectionTitleStyle.Render("IDENTITY RECORD")
	record := identityRecord(report)
	if record == nil {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "not available"))
	}
	if record.Status == correlator.StatusSkipped {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "skipped"), row("Note", empty(record.Note)))
	}

	lines := []string{}
	if top := topVisible(record.Names); top != nil {
		lines = append(lines, row("Top name", candidateLine(*top)))
	} else {
		lines = append(lines, row("Top name", "none above display threshold"))
	}
	if record.Truecaller != nil {
		tc := record.Truecaller
		parts := []string{"sourced from Truecaller"}
		if strings.TrimSpace(tc.Name) != "" {
			parts = append(parts, "name: "+tc.Name)
		}
		if strings.TrimSpace(tc.City) != "" {
			parts = append(parts, "city: "+tc.City)
		}
		if tc.ConfidenceScore > 0 {
			parts = append(parts, fmt.Sprintf("confidence: %.2f", tc.ConfidenceScore))
		}
		if len(tc.Emails) > 0 {
			parts = append(parts, "emails: "+strings.Join(tc.Emails, ", "))
		}
		lines = append(lines, row("Truecaller", strings.Join(parts, " | ")))
	}
	if top := topVisible(record.Addresses); top != nil {
		value := candidateLine(*top)
		if strings.TrimSpace(top.DecayNote) != "" {
			value += " - " + top.DecayNote
		}
		lines = append(lines, row("Top address", value))
	}
	if top := topVisible(record.DOBs); top != nil {
		label := top.Precision
		if label == "" {
			label = "observed"
		}
		lines = append(lines, row("DOB", fmt.Sprintf("%s (%s, %s)", top.DisplayValue, label, top.ConfidenceLabel)))
	}
	if emails := visibleValues(record.Emails, 5); len(emails) > 0 {
		lines = append(lines, row("Email pivots", strings.Join(emails, ", ")))
	}
	for _, conflict := range record.Conflicts {
		lines = append(lines, valueStyle.Render(fmt.Sprintf("- conflict %s: %s [%s] vs %s [%s], penalty %.2f",
			conflict.Field, conflict.ValueA, conflict.SourceA, conflict.ValueB, conflict.SourceB, conflict.PenaltyApplied)))
	}
	if record.SuppressedCount > 0 {
		lines = append(lines, row("Suppressed", fmt.Sprintf("%d below 0.45 confidence; retained in JSON", record.SuppressedCount)))
	}
	if len(lines) == 0 {
		lines = append(lines, row("Status", "no identity candidates found"))
	}
	return lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(lines, "\n"))
}

type RiskScoreBlock struct{}

func (RiskScoreBlock) Render(report *core.InvestigationReport) string {
	risk := report.RiskScore
	if risk == nil {
		risk = core.ScoreRisk(report)
	}

	lines := []string{}
	if len(risk.Drivers) == 0 {
		lines = append(lines, valueStyle.Render("- no contributing drivers"))
	} else {
		for _, driver := range risk.Drivers {
			lines = append(lines, valueStyle.Render(fmt.Sprintf("- %s: %d pts", driver.Label, driver.Points)))
		}
	}

	scoreLine := riskScoreStyle.Render(fmt.Sprintf("RISK SCORE: %d/100 %s", risk.Score, bandStyle(risk.Band).Render(string(risk.Band))))
	lines = append(lines, scoreLine)
	return strings.Join(lines, "\n")
}

var (
	bannerStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#808080")).
			Foreground(lipgloss.Color("#000000")).
			Bold(true).
			Padding(1, 2, 0, 2)
	subtitleBannerStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("#808080")).
				Foreground(lipgloss.Color("#000000")).
				Padding(0, 2, 1, 2)
	sectionTitleStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("212")).
				Bold(true).
				MarginBottom(1)
	labelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245")).
			Width(18)
	valueStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("15"))
	quoteStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("250")).
			PaddingLeft(2)
	breachHitStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196")).
			Bold(true)
	cleanStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("42")).
			Bold(true)
	followupStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			PaddingLeft(2)
	riskScoreStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("15")).
			Bold(true)
)

func banner() string {
	art := " ___ _  _  ___  _  _ ___     _   ___ ___ ___ ___ ___ \n" +
		"| _ \\ || |/ _ \\| \\| | __|   /_\\ / __/ __| __/ __/ __|\n" +
		"|  _/ __ | (_) | .` | _|   / _ \\ (_| (__| _|\\__ \\__ \\\n" +
		"|_| |_||_|\\___/|_|\\_|___| /_/ \\_\\___\\___|___|___/___/"
	subtitle := "Open-source phone number OSINT  ·  v1.0.0  ·  github.com/KatrielMoses/PhoneAccess"
	return bannerStyle.Render(art) + "\n" + subtitleBannerStyle.Render(subtitle)
}

func row(label, value string) string {
	return labelStyle.Render(label) + valueStyle.Render(value)
}

func empty(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

func moduleFindings(report *core.InvestigationReport, name string) map[string]string {
	for _, result := range report.Results {
		if result != nil && result.ModuleName == name {
			return result.Findings
		}
	}
	return nil
}

func moduleResult(report *core.InvestigationReport, name string) *core.ModuleResult {
	for _, result := range report.Results {
		if result != nil && result.ModuleName == name {
			return result
		}
	}
	return nil
}

func withConfidence(value, conf string) string {
	conf = strings.TrimSpace(conf)
	if conf == "" {
		return value
	}
	return fmt.Sprintf("%s %s %s", value, confidenceIcon(conf), conf)
}

func voipStatus(findings map[string]string) string {
	status := "not suspected"
	if strings.EqualFold(findings["voip_suspected"], "true") {
		status = "suspected"
		if provider := strings.TrimSpace(findings["voip_provider"]); provider != "" && provider != "unknown" {
			status += " (" + provider + ")"
		}
	}
	return withConfidence(status, findings["voip_confidence"])
}

func confidenceSummary(findings map[string]string) string {
	keys := []string{"carrier", "line_type", "voip", "timezone"}
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		conf := findings[key+"_confidence"]
		if conf == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s %s", key, confidenceIcon(conf)))
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, ", ")
}

func confidenceIcon(conf string) string {
	switch strings.ToLower(strings.TrimSpace(conf)) {
	case "high":
		return "\u2713"
	case "medium":
		return "~"
	default:
		return "?"
	}
}

func identityRecord(report *core.InvestigationReport) *correlator.UnifiedIdentityRecord {
	if report == nil || report.IdentityRecord == nil {
		return nil
	}
	if record, ok := report.IdentityRecord.(*correlator.UnifiedIdentityRecord); ok {
		return record
	}
	data, err := json.Marshal(report.IdentityRecord)
	if err != nil {
		return nil
	}
	var record correlator.UnifiedIdentityRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil
	}
	return &record
}

func publicRecordsResult(report *core.InvestigationReport) *publicrecords.PublicRecordsResult {
	if report == nil {
		return nil
	}
	for _, result := range report.Results {
		if result == nil || !strings.EqualFold(result.ModuleName, "public_records") {
			continue
		}
		if pr, ok := result.Data.(*publicrecords.PublicRecordsResult); ok {
			return pr
		}
		if result.Data == nil {
			return nil
		}
		data, err := json.Marshal(result.Data)
		if err != nil {
			return nil
		}
		var pr publicrecords.PublicRecordsResult
		if err := json.Unmarshal(data, &pr); err != nil {
			return nil
		}
		return &pr
	}
	return nil
}

func formatEdgarLines(hits []publicrecords.EdgarHit) []string {
	lines := make([]string, 0, len(hits))
	for _, hit := range hits {
		parts := []string{empty(hit.EntityName)}
		if hit.FileDate != "" {
			parts = append(parts, hit.FileDate)
		}
		if hit.FormType != "" {
			parts = append(parts, hit.FormType)
		}
		if hit.FilingURL != "" {
			parts = append(parts, hit.FilingURL)
		}
		lines = append(lines, strings.Join(parts, " | "))
	}
	return lines
}

func formatOfficerLines(hits []publicrecords.OfficerHit) []string {
	lines := make([]string, 0, len(hits))
	for _, hit := range hits {
		parts := []string{empty(hit.OfficerName)}
		if hit.Company != "" {
			parts = append(parts, hit.Company)
		}
		if hit.Jurisdiction != "" {
			parts = append(parts, hit.Jurisdiction)
		}
		if hit.Position != "" {
			parts = append(parts, hit.Position)
		}
		lines = append(lines, strings.Join(parts, " | "))
	}
	return lines
}

func formatCompaniesHouseLines(hits []publicrecords.CompaniesHouseHit) []string {
	lines := make([]string, 0, len(hits))
	for _, hit := range hits {
		parts := []string{empty(hit.OfficerName)}
		if hit.CompanyName != "" {
			parts = append(parts, hit.CompanyName)
		}
		if hit.AppointedOn != "" {
			parts = append(parts, "appointed "+hit.AppointedOn)
		}
		if hit.ResignedOn != "" {
			parts = append(parts, "resigned "+hit.ResignedOn)
		}
		if hit.Appointment != "" {
			parts = append(parts, hit.Appointment)
		}
		lines = append(lines, strings.Join(parts, " | "))
	}
	return lines
}

func formatPacerLines(hits []publicrecords.PacerHit) []string {
	lines := make([]string, 0, len(hits))
	for _, hit := range hits {
		parts := []string{empty(hit.PartyName)}
		if hit.CaseNumber != "" {
			parts = append(parts, hit.CaseNumber)
		}
		if hit.Court != "" {
			parts = append(parts, hit.Court)
		}
		if hit.FilingDate != "" {
			parts = append(parts, hit.FilingDate)
		}
		if hit.CaseType != "" {
			parts = append(parts, hit.CaseType)
		}
		lines = append(lines, strings.Join(parts, " | "))
	}
	return lines
}

func formatLicenseLines(hits []publicrecords.LicenseHit) []string {
	lines := make([]string, 0, len(hits))
	for _, hit := range hits {
		parts := []string{empty(hit.Name)}
		if hit.LicenseType != "" {
			parts = append(parts, hit.LicenseType)
		}
		if hit.State != "" {
			parts = append(parts, hit.State)
		}
		if hit.Status != "" {
			parts = append(parts, hit.Status)
		}
		lines = append(lines, strings.Join(parts, " | "))
	}
	return lines
}

func formatSearchHitLines(hits []search.SearchHit) []string {
	lines := make([]string, 0, len(hits))
	for _, hit := range hits {
		parts := []string{}
		if hit.URL != "" {
			parts = append(parts, hit.URL)
		}
		if hit.Snippet != "" {
			parts = append(parts, hit.Snippet)
		}
		if hit.Title != "" {
			parts = append(parts, hit.Title)
		}
		lines = append(lines, strings.Join(parts, " | "))
	}
	return lines
}

func topVisible(candidates []correlator.FieldCandidate) *correlator.FieldCandidate {
	for i := range candidates {
		if !candidates[i].Suppressed && candidates[i].Confidence >= correlator.LowConfidenceThreshold {
			return &candidates[i]
		}
	}
	return nil
}

func visibleValues(candidates []correlator.FieldCandidate, limit int) []string {
	values := []string{}
	for _, candidate := range candidates {
		if candidate.Suppressed || candidate.Confidence < correlator.LowConfidenceThreshold {
			continue
		}
		values = append(values, candidate.DisplayValue)
		if len(values) == limit {
			break
		}
	}
	return values
}

func candidateLine(candidate correlator.FieldCandidate) string {
	return fmt.Sprintf("%s %s %s (%.2f via %s)",
		candidate.DisplayValue,
		confidenceIcon(candidate.ConfidenceLabel),
		candidate.ConfidenceLabel,
		candidate.Confidence,
		candidateSources(candidate.Sources),
	)
}

func candidateSources(sources []correlator.SourceMeta) string {
	names := make([]string, 0, len(sources))
	for _, source := range sources {
		if source.Name != "" {
			names = append(names, source.Name+" "+source.Tier)
		}
	}
	if len(names) == 0 {
		return "unknown source"
	}
	return strings.Join(names, ", ")
}

func splitSnippets(value string, limit int) []string {
	lines := strings.Split(value, "\n")
	snippets := make([]string, 0, limit)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		snippets = append(snippets, line)
		if len(snippets) == limit {
			break
		}
	}
	return snippets
}

func quoteBlock(snippets []string) string {
	quoted := make([]string, 0, len(snippets))
	for _, snippet := range snippets {
		quoted = append(quoted, quoteStyle.Render("> "+snippet))
	}
	return strings.Join(quoted, "\n")
}

func riskStyle(label string, score int) lipgloss.Style {
	label = strings.ToUpper(strings.TrimSpace(label))
	switch {
	case label == "CLEAN" || score == 0:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	case label == "HIGH" || label == "CRITICAL" || score >= 50:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	case label == "MODERATE" || score >= 25:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("226")).Bold(true)
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Bold(true)
	}
}

func bandStyle(band core.RiskBand) lipgloss.Style {
	switch band {
	case core.RiskBandCritical:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	case core.RiskBandHigh:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("202")).Bold(true)
	case core.RiskBandModerate:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("226")).Bold(true)
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	}
}
