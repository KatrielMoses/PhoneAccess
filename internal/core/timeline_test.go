package core

import "testing"

func TestBuildTimelineSortsMixedSources(t *testing.T) {
	report := &InvestigationReport{
		Results: []*ModuleResult{
			{
				ModuleName: "breach",
				Data: map[string]any{
					"breaches": []any{
						map[string]any{"name": "ExampleDB", "date": "2023-01-01"},
					},
				},
			},
			{
				ModuleName: "search",
				Data: map[string]any{
					"hits": []any{
						map[string]any{
							"title":         "Search result",
							"retrieved_at":  "2024-01-10T10:00:00Z",
							"source":        "google",
							"query_category": "reputation",
						},
					},
				},
			},
			{
				ModuleName: "paste",
				Data: map[string]any{
					"reddit_hits": []any{
						map[string]any{
							"title":       "Reddit hit",
							"subreddit":   "r/test",
							"created_utc": float64(1717000000),
							"url":         "https://reddit.com/r/test",
						},
					},
				},
			},
			{
				ModuleName: "reverse",
				Data: map[string]any{
					"wayback_hits": []any{
						map[string]any{
							"source":     "Truecaller",
							"url":        "https://example.com/profile",
							"first_seen": "2022-01-05",
						},
					},
				},
			},
		},
	}

	timeline := BuildTimeline(report)
	if timeline.FirstSeen != "2022-01-05" {
		t.Fatalf("first_seen = %q, want 2022-01-05", timeline.FirstSeen)
	}
	if timeline.MostRecent != "2024-05-29" {
		t.Fatalf("most_recent = %q, want 2024-05-29", timeline.MostRecent)
	}
	if len(timeline.Events) != 4 {
		t.Fatalf("events = %#v, want 4", timeline.Events)
	}
	if timeline.Events[0].Source != "Truecaller" || timeline.Events[0].EventType != "wayback_index" {
		t.Fatalf("first event = %#v, want wayback first-seen", timeline.Events[0])
	}
	if timeline.Events[3].Source != "reddit" {
		t.Fatalf("last event = %#v, want reddit", timeline.Events[3])
	}
}

