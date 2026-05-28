package exporters

import (
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

func sampleReport() *core.InvestigationReport {
	return &core.InvestigationReport{
		GeneratedAt: time.Date(2026, 5, 27, 6, 0, 0, 123456789, time.UTC),
		Passive:     false,
		Number: &core.PhoneNumber{
			RawInput:          "+14155552671",
			E164:              "+14155552671",
			CountryCode:       1,
			CountryAlpha2:     "US",
			NationalNumber:    "4155552671",
			RegionDescription: "San Francisco, CA",
			LineType:          core.LineTypeMobile,
			CarrierHint:       "Example Wireless",
			Timezone:          "America/Los_Angeles",
			Valid:             true,
		},
		Results: []*core.ModuleResult{
			{
				ModuleName: "carrier",
				Status:     core.ModuleStatusSuccess,
				Findings: map[string]string{
					"carrier":        "Example Wireless",
					"line_type":      "mobile",
					"voip_suspected": "false",
					"timezone":       "America/Los_Angeles",
					"country":        "US",
					"region":         "San Francisco, CA",
					"data_source":    "offline",
				},
				Evidence: []string{"carrier evidence"},
			},
			{
				ModuleName: "spam",
				Status:     core.ModuleStatusSuccess,
				Findings: map[string]string{
					"spam_score":         "35",
					"risk":               "MODERATE",
					"total_reports":      "4",
					"caller_type":        "telemarketer",
					"sources_with_hits":  "ExampleSource",
					"report_snippets":    "First spam report\nSecond spam report",
					"most_recent_report": "2026-05-01",
				},
			},
			{
				ModuleName: "breach",
				Status:     core.ModuleStatusSuccess,
				Findings: map[string]string{
					"found":                "true",
					"breach_count":         "2",
					"stealer_count":        "1",
					"compromised_machines": "1",
					"credentials_found":    "true",
					"breaches":             "ExampleBreach 2024-01-01 [email, phone]\nOtherBreach [password]",
					"data_classes_seen":    "email, phone, password",
				},
				Data: map[string]any{
					"breaches": []map[string]any{
						{"name": "ExampleBreach", "data_classes_exposed": []string{"email", "phone"}},
						{"name": "OtherBreach", "data_classes_exposed": []string{"password"}},
					},
					"data_classes_seen": []string{"email", "phone", "password"},
				},
			},
			{
				ModuleName: "reverse",
				Status:     core.ModuleStatusSuccess,
				Findings: map[string]string{
					"name_hint":         "Jane Example",
					"name_confidence":   "medium",
					"location_hint":     "San Francisco",
					"sources_checked":   "Truecaller, Google",
					"sources_with_hits": "Google",
					"raw_hits":          "Google [low]: Jane Example",
					"pivot_emails":      "jane@example.com",
				},
			},
			{
				ModuleName: "voip",
				Status:     core.ModuleStatusSuccess,
				Findings: map[string]string{
					"is_voip":      "true",
					"confidence":   "high",
					"provider":     "Example VOIP",
					"is_prepaid":   "false",
					"risk_signals": "number matches embedded VOIP provider prefix list",
					"data_source":  "embedded_prefixes",
				},
			},
			{
				ModuleName: "geo",
				Status:     core.ModuleStatusSuccess,
				Findings: map[string]string{
					"area_code_origin":        "San Francisco, CA",
					"area_code_split_history": "true",
					"likely_ported":           "true",
					"local_time":              "2026-05-26 23:00 PDT",
					"utc_offset":              "-07:00",
					"business_hours":          "false",
					"regional_risk_flag":      "false",
				},
			},
		},
		IdentityGraph: &core.IdentityGraph{
			PivotPoints: []core.IdentityPivot{
				{Type: "email", Value: "jane@example.com", Modules: []string{"reverse"}, Confidence: "medium"},
			},
			SuggestedCommands: []string{"mailaccess investigate jane@example.com"},
		},
	}
}
