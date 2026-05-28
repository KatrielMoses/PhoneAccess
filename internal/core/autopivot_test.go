package core

import (
	"context"
	"testing"
	"time"
)

func TestAutoPivotSkipsWhenDepthZero(t *testing.T) {
	calls := 0
	engine := NewAutoPivotEngine(
		WithAutoPivotDepth(0),
		WithAutoPivotUsernameSearcher(func(ctx context.Context, username string) ([]UsernameProfileHit, error) {
			calls++
			return nil, nil
		}),
	)

	report := &InvestigationReport{
		GeneratedAt: time.Now().UTC(),
		Number:      &PhoneNumber{E164: "+14155552671"},
		IdentityGraph: &IdentityGraph{
			PivotPoints: []IdentityPivot{
				{Type: "username", Value: "alice", Confidence: "high"},
			},
		},
	}

	result, err := engine.Run(context.Background(), report)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if calls != 0 {
		t.Fatalf("searcher called %d times, want 0", calls)
	}
	if result.Chain == nil {
		t.Fatal("chain is nil, want root phone node")
	}
	if result.Chain.Type != "phone" || result.Chain.Value != "+14155552671" {
		t.Fatalf("chain = %#v, want root phone node", result.Chain)
	}
	if len(result.Chain.Children) != 0 {
		t.Fatalf("chain has %d children, want 0 when depth=0", len(result.Chain.Children))
	}
}

func TestAutoPivotStopsAtMaxDepthAndPreventsDuplicates(t *testing.T) {
	calls := 0
	engine := NewAutoPivotEngine(
		WithAutoPivotDepth(2),
		WithAutoPivotUsernameSearcher(func(ctx context.Context, username string) ([]UsernameProfileHit, error) {
			calls++
			return []UsernameProfileHit{
				{
					Platform:   "Example",
					URL:        "https://example.com/@repeat",
					Source:     "username_profile",
					Confidence: 1,
				},
			}, nil
		}),
	)

	report := &InvestigationReport{
		GeneratedAt: time.Now().UTC(),
		Number:      &PhoneNumber{E164: "+14155552671"},
		IdentityGraph: &IdentityGraph{
			PivotPoints: []IdentityPivot{
				{Type: "username", Value: "repeat", Confidence: "high"},
				{Type: "username", Value: "repeat", Confidence: "high"},
				{Type: "email", Value: "repeat@example.com", Confidence: "high"},
			},
		},
	}

	result, err := engine.Run(context.Background(), report)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if calls != 1 {
		t.Fatalf("searcher called %d times, want 1", calls)
	}
	if result.Chain == nil || len(result.Chain.Children) != 3 {
		t.Fatalf("chain children = %#v, want three top-level entries including duplicate skip", result.Chain)
	}

	var usernameNode *PivotChainNode
	duplicateSeen := false
	for _, child := range result.Chain.Children {
		if child.Label == "duplicate pivot skipped" {
			duplicateSeen = true
		}
		if child.Type == "username" && child.Label != "duplicate pivot skipped" {
			usernameNode = child
		}
	}
	if usernameNode == nil {
		t.Fatalf("username node missing from chain: %#v", result.Chain.Children)
	}
	if !duplicateSeen {
		t.Fatalf("duplicate pivot skip node missing: %#v", result.Chain.Children)
	}
	platformCount := 0
	for _, child := range usernameNode.Children {
		if child.Type == "platform" && child.Value == "Example" {
			platformCount++
		}
	}
	if platformCount != 1 {
		t.Fatalf("username node children = %#v, want one verified platform hit", usernameNode.Children)
	}
	if len(result.Linked) != 1 {
		t.Fatalf("linked investigations = %#v, want one child report", result.Linked)
	}
	if result.Linked[0].Report == nil || result.Linked[0].Report.PivotChain == nil {
		t.Fatalf("child report pivot chain missing: %#v", result.Linked[0].Report)
	}
	if len(result.Linked[0].Children) != 0 {
		t.Fatalf("duplicate pivot should not recurse, got %#v", result.Linked[0].Children)
	}
}
