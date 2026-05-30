package cli

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
	"github.com/KatrielMoses/PhoneAccess/internal/correlator"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/infrastructure"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/intelligence"
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

func NewTerminalRenderer(minConfidence ...float64) *TerminalRenderer {
	threshold := 0.0
	if len(minConfidence) > 0 && minConfidence[0] > 0 {
		threshold = minConfidence[0]
	}
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
			PhotoIntelligenceBlock{},
			ServiceEnumerationBlock{},
			FinancialFootprintBlock{},
			IdentityGraphBlock{},
			PivotChainBlock{},
			IdentityRecordBlock{MinConfidence: threshold},
			InfrastructureIntelligenceBlock{},
			IntelligenceScreeningBlock{},
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

	// Show a note when HIBP is not configured so users know the most recognised
	// breach database was not queried.
	for _, part := range strings.Split(findings["source_statuses"], "; ") {
		if strings.HasPrefix(part, "HIBP=unavailable") {
			rows = append(rows, valueStyle.Render("~ HIBP: HIBP_API_KEY not configured ($3.50/month \u2014 haveibeenpwned.com/API/Key)"))
			break
		}
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

	// Signal: registration-only check — use custom rendering (no profile details).
	signalFindings := moduleFindings(report, "signal")
	switch {
	case len(signalFindings) == 0:
		lines = append(lines, row("Signal", "~ check unavailable"))
	case signalFindings["error"] != "":
		lines = append(lines, row("Signal", "~ check unavailable"))
	case strings.EqualFold(signalFindings["found"], "true"):
		lines = append(lines, row("Signal", "✓ registered"))
	default:
		lines = append(lines, row("Signal", "— not registered"))
	}

	return lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(lines, "\n"))
}

type PhotoIntelligenceBlock struct{}

func (PhotoIntelligenceBlock) Render(report *core.InvestigationReport) string {
	title := sectionTitleStyle.Render("PHOTO INTELLIGENCE")

	// Check for gated module result first.
	raw := moduleResult(report, "image_intelligence")
	if raw != nil && raw.Status == core.ModuleStatusGated {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "gated — use --active to enable"))
	}

	intel := report.ImageIntelligence
	if intel == nil {
		// Module ran but produced no photo (skipped).
		if raw != nil && raw.Status == core.ModuleStatusSkipped {
			reason := cliFirstNonEmpty(raw.Findings["reason"], "no profile photo retrieved")
			return lipgloss.JoinVertical(lipgloss.Left, title,
				row("Status", "No profile photo retrieved (WhatsApp/Telegram session required)"),
				row("Note", empty(reason)))
		}
		return lipgloss.JoinVertical(lipgloss.Left, title,
			row("Status", "No profile photo retrieved (WhatsApp/Telegram session required)"))
	}

	lines := []string{
		row("Source", empty(intel.PhotoSource)+" profile photo"),
		row("pHash", empty(intel.PhotoPHash)),
	}

	// TinEye results.
	if intel.TinEye.MatchCount == 0 {
		lines = append(lines, row("TinEye", "no reverse matches"))
	} else {
		lines = append(lines, row("TinEye", fmt.Sprintf("%d reverse match(es)", intel.TinEye.MatchCount)))
		for _, m := range intel.TinEye.Matches {
			date := ""
			if !m.CrawlDate.IsZero() {
				date = m.CrawlDate.Format("2006-01-02")
			}
			detail := m.Domain
			if date != "" {
				detail += " (" + date + ")"
			}
			lines = append(lines, valueStyle.Render("  → "+detail))
		}
	}

	// Manual search URLs.
	urls := intel.ReverseURLs
	if urls.GoogleLens != "" || urls.Yandex != "" || urls.Bing != "" {
		lines = append(lines, "")
		lines = append(lines, labelStyle.Render("Manual search URLs:"))
		if urls.GoogleLens != "" {
			lines = append(lines, followupStyle.Render("Google Lens:  "+urls.GoogleLens))
		}
		if urls.Yandex != "" {
			lines = append(lines, followupStyle.Render("Yandex:       "+urls.Yandex))
		}
		if urls.Bing != "" {
			lines = append(lines, followupStyle.Render("Bing:         "+urls.Bing))
		}
	}

	// Cross-session hits.
	for _, hit := range intel.CrossSessionHits {
		date := ""
		if !hit.FoundAt.IsZero() {
			date = hit.FoundAt.Format("2006-01-02")
		}
		detail := fmt.Sprintf("photo matches case #%d (%s)", hit.CaseID, hit.PhoneE164)
		if date != "" {
			detail += " — " + date
		}
		detail += fmt.Sprintf(" — Hamming: %d", hit.HammingDist)
		lines = append(lines, breachHitStyle.Render("  ↔ Cross-session: "+detail))
	}

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

type IdentityRecordBlock struct {
	MinConfidence float64
}

func (b IdentityRecordBlock) Render(report *core.InvestigationReport) string {
	title := sectionTitleStyle.Render("IDENTITY RECORD")
	record := identityRecord(report)
	if record == nil {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "not available"))
	}
	if record.Status == correlator.StatusSkipped {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "skipped"), row("Note", empty(record.Note)))
	}

	lines := []string{}

	// Top name — best available regardless of suppression status.
	if len(record.Names) > 0 {
		lines = append(lines, row("Top name", candidateLine(record.Names[0])))
	} else {
		lines = append(lines, row("Top name", "none found"))
	}

	// Truecaller direct record.
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

	// Names — all candidates with ✓/~/? indicators.
	if len(record.Names) > 0 {
		hidden := appendCandidateSection(&lines, "Names", record.Names, b.MinConfidence)
		if hidden > 0 {
			lines = append(lines, followupStyle.Render(fmt.Sprintf(
				"  (%d findings below %.2f confidence threshold — use --format json to see all)",
				hidden, b.MinConfidence)))
		}
	}

	// Addresses — top summary line + full section when multiple exist.
	if len(record.Addresses) > 0 {
		top := record.Addresses[0]
		value := candidateLine(top)
		if strings.TrimSpace(top.DecayNote) != "" {
			value += " — " + top.DecayNote
		}
		lines = append(lines, row("Top address", value))
		if len(record.Addresses) > 1 {
			hidden := appendCandidateSection(&lines, "Addresses", record.Addresses, b.MinConfidence)
			if hidden > 0 {
				lines = append(lines, followupStyle.Render(fmt.Sprintf(
					"  (%d findings below %.2f confidence threshold — use --format json to see all)",
					hidden, b.MinConfidence)))
			}
		}
	}

	// DOB — top candidate only (multiple DOBs appear in Conflicts).
	if len(record.DOBs) > 0 {
		top := record.DOBs[0]
		label := top.Precision
		if label == "" {
			label = "observed"
		}
		lines = append(lines, row("DOB", fmt.Sprintf("%s (%s, %s)", top.DisplayValue, label, top.ConfidenceLabel)))
	}

	// Email pivots — filtered by minConfidence when set.
	emailVals := make([]string, 0, len(record.Emails))
	for _, c := range record.Emails {
		if b.MinConfidence > 0 && c.Confidence < b.MinConfidence {
			continue
		}
		if len(emailVals) >= 5 {
			break
		}
		emailVals = append(emailVals, c.DisplayValue)
	}
	if len(emailVals) > 0 {
		lines = append(lines, row("Email pivots", strings.Join(emailVals, ", ")))
	}

	// Conflicts.
	for _, conflict := range record.Conflicts {
		lines = append(lines, valueStyle.Render(fmt.Sprintf("- conflict %s: %s [%s] vs %s [%s], penalty %.2f",
			conflict.Field, conflict.ValueA, conflict.SourceA, conflict.ValueB, conflict.SourceB, conflict.PenaltyApplied)))
	}

	if len(lines) == 0 {
		lines = append(lines, row("Status", "no identity candidates found"))
	}
	return lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(lines, "\n"))
}

// appendCandidateSection appends a labelled list of candidates with ✓/~/? indicators.
// Returns the count hidden by minConfidence (0 = show all).
func appendCandidateSection(lines *[]string, label string, candidates []correlator.FieldCandidate, minConfidence float64) int {
	*lines = append(*lines, valueStyle.Render("  "+label+":"))
	hidden := 0
	for _, c := range candidates {
		if minConfidence > 0 && c.Confidence < minConfidence {
			hidden++
			continue
		}
		indicator := confidenceTierIndicator(c.Confidence)
		src := sourceNamesShort(c.Sources)
		*lines = append(*lines, valueStyle.Render(fmt.Sprintf("    %s %-24s  %.2f  [%s]", indicator, c.DisplayValue, c.Confidence, src)))
	}
	return hidden
}

// confidenceTierIndicator returns ✓ for ≥0.65, ~ for 0.45–0.64, ? for <0.45.
func confidenceTierIndicator(confidence float64) string {
	switch {
	case confidence >= correlator.MediumConfidenceThreshold:
		return "✓"
	case confidence >= correlator.LowConfidenceThreshold:
		return "~"
	default:
		return "?"
	}
}

// sourceNamesShort returns a comma-joined list of source names (no tier suffix).
func sourceNamesShort(sources []correlator.SourceMeta) string {
	names := make([]string, 0, len(sources))
	for _, s := range sources {
		if s.Name != "" {
			names = append(names, s.Name)
		}
	}
	return strings.Join(names, ", ")
}

type InfrastructureIntelligenceBlock struct{}

func (InfrastructureIntelligenceBlock) Render(report *core.InvestigationReport) string {
	title := sectionTitleStyle.Render("INFRASTRUCTURE INTELLIGENCE")

	raw := moduleResult(report, "infrastructure")
	if raw == nil {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "not available"))
	}
	if raw.Status == core.ModuleStatusGated {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "gated — use --active to enable"))
	}

	result := infraResult(raw)
	if result == nil {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "not available"))
	}

	lines := []string{}

	// Certificates
	certCount := len(result.CertHits)
	if certCount == 0 {
		lines = append(lines, row("Certificates", "no hits"))
	} else {
		lines = append(lines, row("Certificates", fmt.Sprintf("%d domain(s) found via SSL CT logs", certCount)))
		for _, hit := range result.CertHits {
			detail := hit.Domain
			if hit.IssuedAt != "" {
				detail += " (issued " + hit.IssuedAt
				if hit.Issuer != "" {
					detail += ", " + hit.Issuer
				}
				detail += ")"
			}
			lines = append(lines, cleanStyle.Render("  ✓ "+detail))
		}
	}

	// WHOIS / RDAP
	whoisCount := len(result.WhoisHits)
	if whoisCount == 0 {
		lines = append(lines, row("WHOIS", "no hits"))
	} else {
		lines = append(lines, row("WHOIS", fmt.Sprintf("%d registrant match(es)", whoisCount)))
		for _, hit := range result.WhoisHits {
			detail := hit.Domain + " — Registrant: "
			if hit.RegistrantName != "" {
				detail += hit.RegistrantName
			} else {
				detail += "unknown"
			}
			if hit.RegistrantEmail != "" {
				detail += ", " + hit.RegistrantEmail
			}
			if hit.RegistrationDate != "" {
				detail += " (" + hit.RegistrationDate + ")"
			}
			lines = append(lines, cleanStyle.Render("  ✓ "+detail))
		}
	}

	// VirusTotal
	findings := raw.Findings
	vtConfigured := strings.EqualFold(findings["vt_configured"], "true")
	vtHitCount, _ := strconv.Atoi(findings["vt_hit_count"])

	var vtLine string
	var vtStyle lipgloss.Style
	switch {
	case !vtConfigured:
		vtLine = "no hits  (VIRUSTOTAL_API_KEY not configured)"
		vtStyle = valueStyle
	case vtHitCount > 0:
		vtLine = fmt.Sprintf("%d hit(s)", vtHitCount)
		if labels := strings.TrimSpace(findings["vt_threat_labels"]); labels != "" {
			vtLine += " — " + labels
		}
		vtStyle = breachHitStyle
	default:
		vtLine = "no hits"
		vtStyle = valueStyle
	}
	lines = append(lines, row("VirusTotal", vtStyle.Render(vtLine)))

	// MalwareBazaar
	mbCount, _ := strconv.Atoi(findings["malware_sample_count"])
	var mbLine string
	var mbStyle lipgloss.Style
	if mbCount > 0 {
		mbLine = fmt.Sprintf("%d sample(s) found", mbCount)
		if families := strings.TrimSpace(findings["malware_families"]); families != "" {
			mbLine += " — " + families
		}
		mbStyle = breachHitStyle
	} else {
		mbLine = "no hits"
		mbStyle = valueStyle
	}
	lines = append(lines, row("MalwareBazaar", mbStyle.Render(mbLine)))

	return lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(lines, "\n"))
}

func infraResult(result *core.ModuleResult) *infrastructure.InfrastructureResult {
	if result == nil || result.Data == nil {
		return nil
	}
	if r, ok := result.Data.(infrastructure.InfrastructureResult); ok {
		return &r
	}
	data, err := json.Marshal(result.Data)
	if err != nil {
		return nil
	}
	var r infrastructure.InfrastructureResult
	if err := json.Unmarshal(data, &r); err != nil {
		return nil
	}
	return &r
}

type IntelligenceScreeningBlock struct{}

func (IntelligenceScreeningBlock) Render(report *core.InvestigationReport) string {
	title := sectionTitleStyle.Render("INTELLIGENCE SCREENING")

	raw := moduleResult(report, "intelligence")
	if raw == nil {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "not available"))
	}
	if raw.Status == core.ModuleStatusGated {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "gated — use --active to enable"))
	}

	intel := intelligenceResult(raw)
	if intel == nil {
		return lipgloss.JoinVertical(lipgloss.Left, title, row("Status", "not available"))
	}

	lines := []string{}

	// Sanctions section.
	sanctions := intel.Sanctions
	hitCount := len(sanctions.Hits)
	switch {
	case hitCount == 0:
		listCount := len(sanctions.ListsChecked)
		note := fmt.Sprintf("clean (%d+ lists checked)", listCount+94)
		lines = append(lines, row("Sanctions", cleanStyle.Render(note)))
	case sanctions.HighRisk:
		lines = append(lines, row("Sanctions", breachHitStyle.Render(fmt.Sprintf("%d hit (HIGH RISK)", hitCount))))
	default:
		lines = append(lines, row("Sanctions", valueStyle.Render(fmt.Sprintf("%d hit", hitCount))))
	}
	for _, hit := range sanctions.Hits {
		parts := []string{hit.Name}
		if hit.Position != "" {
			parts = append(parts, hit.Position)
		}
		datasets := strings.Join(hit.Datasets, ", ")
		detail := fmt.Sprintf("score: %.2f — [%s]", hit.Score, datasets)
		hitStyle := valueStyle
		if hit.Score >= 0.85 {
			hitStyle = breachHitStyle
		}
		lines = append(lines, hitStyle.Render(fmt.Sprintf("  ✓ %s — %s", strings.Join(parts, " — "), detail)))
	}

	// Adverse media section.
	media := intel.Media
	switch {
	case media.ArticleCount == 0:
		lines = append(lines, row("Adverse Media", cleanStyle.Render("no adverse coverage found")))
	default:
		lines = append(lines, row("Adverse Media", valueStyle.Render(fmt.Sprintf("%d article(s)", media.ArticleCount))))
		shown := 0
		for _, a := range media.Articles {
			if shown >= 2 {
				remaining := len(media.Articles) - shown
				if remaining > 0 {
					lines = append(lines, valueStyle.Render(fmt.Sprintf("  ~ %d more article(s)", remaining)))
				}
				break
			}
			date := ""
			if !a.PublishedAt.IsZero() {
				date = a.PublishedAt.Format("2006-01-02")
			}
			line := fmt.Sprintf("  ✓ %q — %s", a.Title, a.Source)
			if date != "" {
				line += fmt.Sprintf(" (%s)", date)
			}
			lines = append(lines, breachHitStyle.Render(line))
			shown++
		}
	}

	return lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(lines, "\n"))
}

func intelligenceResult(result *core.ModuleResult) *intelligence.IntelligenceResult {
	if result == nil || result.Data == nil {
		return nil
	}
	if r, ok := result.Data.(intelligence.IntelligenceResult); ok {
		return &r
	}
	data, err := json.Marshal(result.Data)
	if err != nil {
		return nil
	}
	var r intelligence.IntelligenceResult
	if err := json.Unmarshal(data, &r); err != nil {
		return nil
	}
	return &r
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
			Foreground(lipgloss.Color("244"))
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
	return bannerStyle.Render(
		"██████╗ ██╗  ██╗ ██████╗ ███╗   ██╗███████╗     █████╗  ██████╗ ██████╗███████╗███████╗███████╗\n" +
			"██╔══██╗██║  ██║██╔═══██╗████╗  ██║██╔════╝    ██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝\n" +
			"██████╔╝███████║██║   ██║██╔██╗ ██║█████╗      ███████║██║     ██║     █████╗  ███████╗███████╗\n" +
			"██╔═══╝ ██╔══██║██║   ██║██║╚██╗██║██╔══╝      ██╔══██║██║     ██║     ██╔══╝  ╚════██║╚════██║\n" +
			"██║     ██║  ██║╚██████╔╝██║ ╚████║███████╗    ██║  ██║╚██████╗╚██████╗███████╗███████║███████║\n" +
			"╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝╚══════╝╚══════╝╚══════╝",
	)
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
