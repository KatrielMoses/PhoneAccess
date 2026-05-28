package exporters

import (
	"encoding/json"
	"encoding/xml"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

func TestGEXFExporterProducesValidGraph(t *testing.T) {
	report := exportFixtureReport()
	var buf strings.Builder
	if err := (GEXFExporter{}).Export(report, &buf); err != nil {
		t.Fatalf("export gexf: %v", err)
	}
	data := buf.String()
	if err := validateXML(data); err != nil {
		t.Fatalf("gexf xml invalid: %v\n%s", err, data)
	}
	if got := strings.Count(data, "<node "); got != 10 {
		t.Fatalf("node count = %d, want 10", got)
	}
	if got := strings.Count(data, "<edge "); got != 8 {
		t.Fatalf("edge count = %d, want 8", got)
	}
	for _, want := range []string{
		`viz:color r="255" g="0" b="0"`,
		`viz:color r="0" g="102" b="255"`,
		`viz:color r="0" g="153" b="0"`,
		`viz:color r="255" g="153" b="0"`,
		`viz:color r="153" g="0" b="204"`,
		`viz:color r="204" g="204" b="0"`,
	} {
		if !strings.Contains(data, want) {
			t.Fatalf("gexf missing color %q", want)
		}
	}
}

func TestGEXFExporterHandlesEmptyReport(t *testing.T) {
	var buf strings.Builder
	if err := (GEXFExporter{}).Export(&core.InvestigationReport{}, &buf); err != nil {
		t.Fatalf("export gexf empty report: %v", err)
	}
	data := buf.String()
	if err := validateXML(data); err != nil {
		t.Fatalf("empty gexf xml invalid: %v", err)
	}
	if strings.Count(data, "<node ") != 0 || strings.Count(data, "<edge ") != 0 {
		t.Fatalf("empty gexf should not contain nodes or edges: %s", data)
	}
}

func TestJSONLDExporterIncludesURLsAndOmitsMissingName(t *testing.T) {
	report := exportFixtureReport()
	report.IdentityGraph = &core.IdentityGraph{
		PivotPoints: []core.IdentityPivot{
			{Type: "email", Value: "jane@example.com", Modules: []string{"reverse"}, Confidence: "high"},
			{Type: "username", Value: "janeroe", Modules: []string{"reverse"}, Confidence: "high"},
		},
	}

	var buf strings.Builder
	if err := (JSONLDExporter{}).Export(report, &buf); err != nil {
		t.Fatalf("export jsonld: %v", err)
	}

	var data map[string]any
	if err := json.Unmarshal([]byte(buf.String()), &data); err != nil {
		t.Fatalf("jsonld decode: %v", err)
	}

	if _, ok := data["name"]; ok {
		t.Fatalf("expected name field to be omitted when no name is found")
	}

	sameAs := stringsFromJSON(data["sameAs"])
	for _, want := range []string{"https://instagram.com/janeroe", "https://tiktok.com/@janeroe"} {
		if !containsValue(sameAs, want) {
			t.Fatalf("sameAs missing %q: %#v", want, sameAs)
		}
	}

	memberOf := jsonArray(data["memberOf"])
	if len(memberOf) != 1 {
		t.Fatalf("memberOf = %#v, want 1 organization", memberOf)
	}

	identifier := jsonArray(data["identifier"])
	if len(identifier) != 2 {
		t.Fatalf("identifier = %#v, want 2 property values", identifier)
	}
}

func exportFixtureReport() *core.InvestigationReport {
	return &core.InvestigationReport{
		GeneratedAt: time.Date(2026, 5, 27, 6, 0, 0, 0, time.UTC),
		Number: &core.PhoneNumber{
			RawInput:       "+14155552671",
			E164:           "+14155552671",
			CountryCode:    1,
			CountryAlpha2:  "US",
			NationalNumber: "4155552671",
			Valid:          true,
		},
		Results: []*core.ModuleResult{
			{
				ModuleName: "enumerator",
				Status:     core.ModuleStatusSuccess,
				Findings: map[string]string{
					"hits": "[social]\nInstagram\n[finance]\nVenmo",
				},
			},
			{
				ModuleName: "breach",
				Status:     core.ModuleStatusSuccess,
				Findings: map[string]string{
					"breach_count": "1",
					"breaches":     "ExampleBreach",
				},
				Data: map[string]any{
					"breaches": []map[string]any{{"name": "ExampleBreach"}},
				},
			},
			{
				ModuleName: "public_records",
				Status:     core.ModuleStatusSuccess,
				Data: map[string]any{
					"names": []string{"Example Company Inc."},
				},
			},
		},
		IdentityGraph: &core.IdentityGraph{
			PivotPoints: []core.IdentityPivot{
				{Type: "name", Value: "Jane Example", Modules: []string{"reverse"}, Confidence: "medium"},
				{Type: "email", Value: "jane@example.com", Modules: []string{"reverse"}, Confidence: "high"},
				{Type: "username", Value: "janeroe", Modules: []string{"reverse"}, Confidence: "high"},
			},
		},
		PivotChain: &core.PivotChainNode{
			Type:  "phone",
			Value: "+14155552671",
			Children: []*core.PivotChainNode{
				{
					Type:            "email",
					Value:           "jane@example.com",
					Label:           "→ Pivot: mailaccess investigate jane@example.com",
					Confidence:      0.75,
					ConfidenceLabel: "high",
				},
				{
					Type:            "username",
					Value:           "janeroe",
					Confidence:      0.90,
					ConfidenceLabel: "high",
					Children: []*core.PivotChainNode{
						{
							Type:            "platform",
							Value:           "Instagram",
							URL:             "https://instagram.com/janeroe",
							Source:          "username_profile",
							Confidence:      1.0,
							ConfidenceLabel: "verified",
						},
						{
							Type:            "platform",
							Value:           "TikTok",
							URL:             "https://tiktok.com/@janeroe",
							Source:          "username_profile",
							Confidence:      1.0,
							ConfidenceLabel: "verified",
						},
					},
				},
			},
		},
	}
}

func validateXML(data string) error {
	decoder := xml.NewDecoder(strings.NewReader(data))
	for {
		if _, err := decoder.Token(); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func stringsFromJSON(value any) []string {
	switch v := value.(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if text, ok := item.(string); ok {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}

func jsonArray(value any) []any {
	if arr, ok := value.([]any); ok {
		return arr
	}
	return nil
}

func containsValue(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
