package core

import "testing"

func TestRiskBandBoundaries(t *testing.T) {
	tests := []struct {
		score int
		want  RiskBand
	}{
		{0, RiskBandLow},
		{24, RiskBandLow},
		{25, RiskBandModerate},
		{49, RiskBandModerate},
		{50, RiskBandHigh},
		{74, RiskBandHigh},
		{75, RiskBandCritical},
		{100, RiskBandCritical},
	}

	for _, tt := range tests {
		if got := RiskBandForScore(tt.score); got != tt.want {
			t.Fatalf("RiskBandForScore(%d) = %s, want %s", tt.score, got, tt.want)
		}
	}
}

func TestRiskScorerSelectsTopDrivers(t *testing.T) {
	report := riskReport(
		result("spam", map[string]string{"spam_score": "90"}),
		result("voip", map[string]string{"is_voip": "true", "confidence": "high"}),
		result("breach", map[string]string{"breach_count": "3", "stealer_count": "1"}),
		result("geo", map[string]string{"regional_risk_flag": "true"}),
	)

	score := ScoreRisk(report)
	if len(score.Drivers) != 3 {
		t.Fatalf("drivers len = %d, want 3", len(score.Drivers))
	}
	want := []string{"spam reputation", "confirmed VOIP or disposable line", "breach or stealer-log exposure"}
	for i, label := range want {
		if score.Drivers[i].Label != label {
			t.Fatalf("driver[%d] = %q, want %q; drivers=%#v", i, score.Drivers[i].Label, label, score.Drivers)
		}
	}
}

func TestRiskScorerZeroFindingReportScoresZero(t *testing.T) {
	score := ScoreRisk(riskReport(
		result("spam", map[string]string{"spam_score": "0"}),
		result("voip", map[string]string{"is_voip": "false"}),
		result("breach", map[string]string{"breach_count": "0", "stealer_count": "0"}),
		result("geo", map[string]string{"regional_risk_flag": "false"}),
	))

	if score.Score != 0 {
		t.Fatalf("score = %d, want 0", score.Score)
	}
	if score.Band != RiskBandLow {
		t.Fatalf("band = %s, want LOW", score.Band)
	}
	if len(score.Drivers) != 0 {
		t.Fatalf("drivers = %#v, want none", score.Drivers)
	}
}

func TestRiskScorerCountsIdentityRecordNameHit(t *testing.T) {
	report := riskReport(
		result("spam", map[string]string{"spam_score": "0"}),
		result("voip", map[string]string{"is_voip": "false"}),
		result("breach", map[string]string{"breach_count": "0", "stealer_count": "0"}),
		result("geo", map[string]string{"regional_risk_flag": "false"}),
	)
	report.IdentityRecord = map[string]any{
		"status": "success",
		"names": []map[string]any{
			{"display_value": "Jane Example", "confidence": 0.65, "suppressed": false},
		},
	}

	score := ScoreRisk(report)
	if score.Score != 5 {
		t.Fatalf("score = %d, want 5", score.Score)
	}
	if len(score.Drivers) != 1 || score.Drivers[0].Label != "linked identity data" {
		t.Fatalf("drivers = %#v, want linked identity data", score.Drivers)
	}
}

func TestRiskScorerIgnoresSuppressedIdentityRecordName(t *testing.T) {
	report := riskReport()
	report.IdentityRecord = map[string]any{
		"status": "success",
		"names": []map[string]any{
			{"display_value": "Jane Example", "confidence": 0.44, "suppressed": true},
		},
	}

	score := ScoreRisk(report)
	if score.Score != 0 {
		t.Fatalf("score = %d, want 0", score.Score)
	}
}

func TestRiskScorerAllHitReportScoresNearMaximum(t *testing.T) {
	report := riskReport(
		result("spam", map[string]string{"spam_score": "100"}),
		result("voip", map[string]string{"is_voip": "true", "confidence": "high"}),
		result("breach", map[string]string{"breach_count": "4", "stealer_count": "2", "credentials_found": "true"}),
		result("social", map[string]string{"linked_accounts": "WhatsApp, Telegram, Signal"}),
		result("geo", map[string]string{"regional_risk_flag": "true"}),
	)
	report.IdentityGraph = &IdentityGraph{PivotPoints: []IdentityPivot{
		{Type: "name", Value: "Jane Example", Modules: []string{"reverse"}, Confidence: "medium"},
		{Type: "email", Value: "jane@example.com", Modules: []string{"breach"}, Confidence: "medium"},
	}}

	score := ScoreRisk(report)
	if score.Score < 95 {
		t.Fatalf("score = %d, want near 100", score.Score)
	}
	if score.Band != RiskBandCritical {
		t.Fatalf("band = %s, want CRITICAL", score.Band)
	}
}

func riskReport(results ...*ModuleResult) *InvestigationReport {
	report := &InvestigationReport{Results: results}
	report.IdentityGraph = BuildIdentityGraph(report)
	return report
}

func result(name string, findings map[string]string) *ModuleResult {
	return &ModuleResult{
		ModuleName: name,
		Status:     ModuleStatusSuccess,
		Findings:   findings,
	}
}
