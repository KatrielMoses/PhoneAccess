package core

import (
	"testing"
	"time"
)

func TestIdentityGraphBuildsFromMixedModuleResults(t *testing.T) {
	report := &InvestigationReport{
		GeneratedAt: time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC),
		Results: []*ModuleResult{
			{
				ModuleName: "reverse",
				Status:     ModuleStatusSuccess,
				Findings: map[string]string{
					"name_hint":       "Jane Roe",
					"pivot_emails":    "jane.roe@example.com",
					"pivot_usernames": "janeroe",
				},
			},
			{
				ModuleName: "breach",
				Status:     ModuleStatusSuccess,
				Findings: map[string]string{
					"emails": "jane.roe@example.com",
				},
			},
			{
				ModuleName: "spam",
				Status:     ModuleStatusSuccess,
				Findings: map[string]string{
					"report_snippets": "No identity data here.",
				},
			},
		},
	}

	graph := BuildIdentityGraph(report)

	email := findPivot(graph, "email", "jane.roe@example.com")
	if email == nil {
		t.Fatalf("email pivot missing: %#v", graph.PivotPoints)
	}
	if email.Confidence != "high" || len(email.Modules) != 2 {
		t.Fatalf("email pivot = %#v, want high confidence with two modules", email)
	}
	if graph.PivotPoints[0].Type != "email" {
		t.Fatalf("first pivot = %#v, want corroborated email ranked first", graph.PivotPoints[0])
	}

	username := findPivot(graph, "username", "janeroe")
	if username == nil {
		t.Fatalf("username pivot missing: %#v", graph.PivotPoints)
	}
	if !containsString(graph.SuggestedCommands, "mailaccess investigate jane.roe@example.com") {
		t.Fatalf("suggested commands = %#v, want mailaccess command", graph.SuggestedCommands)
	}
}

func TestSearchModulePivotsRemainLowConfidence(t *testing.T) {
	report := &InvestigationReport{
		GeneratedAt: time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC),
		Results: []*ModuleResult{
			{
				ModuleName: "search",
				Status:     ModuleStatusSuccess,
				Findings: map[string]string{
					"emails":       "jane.roe@example.com",
					"names":        "Jane Roe",
					"social_links": "https://example.com/profile",
				},
			},
		},
	}

	graph := BuildIdentityGraph(report)

	email := findPivot(graph, "email", "jane.roe@example.com")
	if email == nil {
		t.Fatalf("email pivot missing: %#v", graph.PivotPoints)
	}
	if email.Confidence != "low" {
		t.Fatalf("email confidence = %q, want low for snippet-derived search pivot", email.Confidence)
	}
}

func findPivot(graph *IdentityGraph, kind, value string) *IdentityPivot {
	for i := range graph.PivotPoints {
		pivot := &graph.PivotPoints[i]
		if pivot.Type == kind && pivot.Value == value {
			return pivot
		}
	}
	return nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
