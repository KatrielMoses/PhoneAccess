package core

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

func ScoreRisk(report *InvestigationReport) *RiskScore {
	if report == nil {
		return zeroRiskScore()
	}

	components := []RiskDriver{
		spamRisk(report),
		voipRisk(report),
		breachRisk(report),
		footprintRisk(report),
		financeRisk(report),
		identityRisk(report),
		geoRisk(report),
	}

	total := 0
	for _, component := range components {
		total += component.Points
	}
	total = clampInt(total, 0, 100)

	drivers := topRiskDrivers(components, 3)
	score := &RiskScore{
		Score:   total,
		Band:    RiskBandForScore(total),
		Drivers: drivers,
		Summary: riskSummary(total, drivers),
	}
	return score
}

func RiskBandForScore(score int) RiskBand {
	switch {
	case score < 25:
		return RiskBandLow
	case score < 50:
		return RiskBandModerate
	case score < 75:
		return RiskBandHigh
	default:
		return RiskBandCritical
	}
}

func zeroRiskScore() *RiskScore {
	return &RiskScore{
		Score:   0,
		Band:    RiskBandLow,
		Drivers: []RiskDriver{},
		Summary: "No risk indicators were found in the completed module results.",
	}
}

func spamRisk(report *InvestigationReport) RiskDriver {
	score := atoi(finding(report, "spam", "spam_score"))
	points := int(math.Round(float64(clampInt(score, 0, 100)) * 0.30))
	return RiskDriver{Label: "spam reputation", Points: points}
}

func voipRisk(report *InvestigationReport) RiskDriver {
	voipFindings := moduleFindings(report, "voip")
	carrierFindings := moduleFindings(report, "carrier")

	if truthy(voipFindings["is_voip"]) && confidenceRank(voipFindings["confidence"]) >= confidenceRank("medium") {
		return RiskDriver{Label: "confirmed VOIP or disposable line", Points: 20}
	}
	if strings.EqualFold(voipFindings["line_type"], string(LineTypeVoIP)) ||
		strings.EqualFold(carrierFindings["line_type"], string(LineTypeVoIP)) {
		return RiskDriver{Label: "confirmed VOIP or disposable line", Points: 20}
	}
	if truthy(voipFindings["is_voip"]) || truthy(carrierFindings["voip_suspected"]) {
		return RiskDriver{Label: "suspected VOIP or disposable line", Points: 10}
	}
	return RiskDriver{Label: "VOIP or disposable line", Points: 0}
}

func breachRisk(report *InvestigationReport) RiskDriver {
	breachCount := atoi(finding(report, "breach", "breach_count"))
	stealerCount := atoi(finding(report, "breach", "stealer_count"))
	credentialsFound := truthy(finding(report, "breach", "credentials_found"))

	points := clampInt(breachCount*4, 0, 12)
	if stealerCount > 0 {
		points += clampInt(stealerCount*3, 0, 6)
	}
	if credentialsFound {
		points += 3
	}
	return RiskDriver{Label: "breach or stealer-log exposure", Points: clampInt(points, 0, 15)}
}

func footprintRisk(report *InvestigationReport) RiskDriver {
	accounts := map[string]bool{}
	for _, result := range report.Results {
		if result == nil || result.Status != ModuleStatusSuccess {
			continue
		}
		collectAccountValues(result.Findings, accounts)
		collectAccountValuesFromData(result.Data, accounts)
	}
	if report.IdentityGraph != nil {
		for _, pivot := range report.IdentityGraph.PivotPoints {
			if pivot.Type == "linked_account" || pivot.Type == "username" {
				accounts[strings.ToLower(pivot.Type+":"+pivot.Value)] = true
			}
		}
	}

	points := clampInt(len(accounts)*5, 0, 15)
	
	enumeratorHits := atoi(finding(report, "enumerator", "hit_count"))
	if enumeratorHits > 0 {
		enumPoints := int(math.Round(float64(enumeratorHits) * 15.0 / 50.0))
		points += enumPoints
	}
	points = clampInt(points, 0, 15)

	return RiskDriver{Label: "messaging or social footprint", Points: points}
}

func identityRisk(report *InvestigationReport) RiskDriver {
	points := 0
	if report.IdentityGraph != nil {
		for _, pivot := range report.IdentityGraph.PivotPoints {
			if !pivotHasIdentitySource(pivot) {
				continue
			}
			switch pivot.Type {
			case "name", "email":
				points += 5
			case "username", "linked_account":
				points += 3
			}
		}
	}
	points += identityRecordPoints(report.IdentityRecord)
	return RiskDriver{Label: "linked identity data", Points: clampInt(points, 0, 10)}
}

func identityRecordPoints(record any) int {
	if record == nil {
		return 0
	}
	type identityRecord struct {
		Status      string              `json:"status"`
		Names       []identityCandidate `json:"names"`
		Addresses   []identityCandidate `json:"addresses"`
		DOBs        []identityCandidate `json:"dobs"`
		Emails      []identityCandidate `json:"emails"`
		SocialLinks []identityCandidate `json:"social_links"`
	}
	var decoded identityRecord
	encoded, err := json.Marshal(record)
	if err != nil || json.Unmarshal(encoded, &decoded) != nil || decoded.Status == "skipped" {
		return 0
	}
	points := 0
	if hasDisplayableIdentityCandidate(decoded.Names) {
		points += 5
	}
	if hasDisplayableIdentityCandidate(decoded.Emails) {
		points += 5
	}
	if hasDisplayableIdentityCandidate(decoded.Addresses) {
		points += 3
	}
	if hasDisplayableIdentityCandidate(decoded.DOBs) {
		points += 3
	}
	if hasDisplayableIdentityCandidate(decoded.SocialLinks) {
		points += 3
	}
	return points
}

type identityCandidate struct {
	Confidence float64 `json:"confidence"`
	Suppressed bool    `json:"suppressed"`
}

func hasDisplayableIdentityCandidate(candidates []identityCandidate) bool {
	for _, candidate := range candidates {
		if !candidate.Suppressed && candidate.Confidence >= 0.45 {
			return true
		}
	}
	return false
}

func pivotHasIdentitySource(pivot IdentityPivot) bool {
	for _, module := range pivot.Modules {
		switch module {
		case "geo", "carrier", "voip":
			continue
		default:
			return true
		}
	}
	return false
}

func geoRisk(report *InvestigationReport) RiskDriver {
	if truthy(finding(report, "geo", "regional_risk_flag")) {
		return RiskDriver{Label: "geographic risk flag", Points: 10}
	}
	return RiskDriver{Label: "geographic risk flag", Points: 0}
}

func financeRisk(report *InvestigationReport) RiskDriver {
	hitCount := atoi(finding(report, "finance", "hit_count"))
	venmoName := strings.TrimSpace(finding(report, "finance", "venmo_display_name"))

	points := 0
	if venmoName != "" {
		points += 10
	}
	if hitCount >= 5 {
		points += 10
	} else if hitCount >= 3 {
		points += 5
	}
	return RiskDriver{Label: "financial platform presence", Points: clampInt(points, 0, 15)}
}

func topRiskDrivers(drivers []RiskDriver, limit int) []RiskDriver {
	out := make([]RiskDriver, 0, len(drivers))
	for _, driver := range drivers {
		if driver.Points > 0 {
			out = append(out, driver)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Points == out[j].Points {
			return out[i].Label < out[j].Label
		}
		return out[i].Points > out[j].Points
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func riskSummary(score int, drivers []RiskDriver) string {
	band := RiskBandForScore(score)
	if score == 0 || len(drivers) == 0 {
		return "No risk indicators were found in the completed module results."
	}
	names := make([]string, 0, len(drivers))
	for _, driver := range drivers {
		names = append(names, driver.Label)
	}
	return fmt.Sprintf("%s risk score driven primarily by %s.", band, humanJoin(names))
}

func humanJoin(values []string) string {
	switch len(values) {
	case 0:
		return ""
	case 1:
		return values[0]
	case 2:
		return values[0] + " and " + values[1]
	default:
		return strings.Join(values[:len(values)-1], ", ") + ", and " + values[len(values)-1]
	}
}

func moduleFindings(report *InvestigationReport, name string) map[string]string {
	if report == nil {
		return nil
	}
	for _, result := range report.Results {
		if result != nil && result.ModuleName == name && result.Findings != nil {
			return result.Findings
		}
	}
	return nil
}

func finding(report *InvestigationReport, moduleName, key string) string {
	return strings.TrimSpace(moduleFindings(report, moduleName)[key])
}

func collectAccountValues(findings map[string]string, accounts map[string]bool) {
	for key, value := range findings {
		key = strings.ToLower(strings.TrimSpace(key))
		if !accountKey(key) {
			continue
		}
		for _, part := range splitRiskList(value) {
			if !isUnknownRiskValue(part) {
				accounts[key+":"+strings.ToLower(part)] = true
			}
		}
	}
}

func collectAccountValuesFromData(data any, accounts map[string]bool) {
	if data == nil {
		return
	}
	switch data.(type) {
	case map[string]any, []any:
	default:
		encoded, err := json.Marshal(data)
		if err == nil {
			var decoded any
			if json.Unmarshal(encoded, &decoded) == nil {
				data = decoded
			}
		}
	}
	switch v := data.(type) {
	case map[string]any:
		for key, child := range v {
			if accountKey(key) {
				for _, part := range valuesFromAny(child) {
					if !isUnknownRiskValue(part) {
						accounts[strings.ToLower(key)+":"+strings.ToLower(part)] = true
					}
				}
				continue
			}
			collectAccountValuesFromData(child, accounts)
		}
	case []any:
		for _, child := range v {
			collectAccountValuesFromData(child, accounts)
		}
	}
}

func valuesFromAny(value any) []string {
	switch v := value.(type) {
	case string:
		return splitRiskList(v)
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, child := range v {
			out = append(out, valuesFromAny(child)...)
		}
		return out
	case map[string]any:
		out := []string{}
		for _, key := range []string{"name", "handle", "username", "profile", "platform"} {
			if text, ok := v[key].(string); ok {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}

func accountKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	return strings.Contains(key, "account") ||
		strings.Contains(key, "profile") ||
		strings.Contains(key, "social") ||
		strings.Contains(key, "messaging") ||
		strings.Contains(key, "telegram") ||
		strings.Contains(key, "whatsapp") ||
		strings.Contains(key, "signal") ||
		strings.Contains(key, "username") ||
		strings.Contains(key, "handle")
}

func splitRiskList(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == ';' || r == '|'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func isUnknownRiskValue(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "unknown", "none", "not available", "false", "true", "skipped":
		return true
	default:
		return false
	}
}

func atoi(value string) int {
	i, _ := strconv.Atoi(strings.TrimSpace(value))
	return i
}

func truthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "yes", "1", "detected", "suspected", "found":
		return true
	default:
		return false
	}
}

func confidenceRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func clampInt(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}
