package exporters

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestJSONExporterValidOutput(t *testing.T) {
	var buf bytes.Buffer
	if err := (JSONExporter{}).Export(sampleReport(), &buf); err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid json: %v", err)
	}

	if decoded["generated_at"] != "2026-05-27T06:00:00Z" {
		t.Fatalf("generated_at = %v, want RFC3339 seconds", decoded["generated_at"])
	}
	if decoded["number"] == nil || decoded["results"] == nil || decoded["identity_graph"] == nil {
		t.Fatalf("top-level report fields missing: %#v", decoded)
	}
	for _, key := range []string{"carrier", "spam", "breach", "reverse", "voip", "geo"} {
		if decoded[key] == nil {
			t.Fatalf("module key %q missing from json", key)
		}
	}

	number, ok := decoded["number"].(map[string]any)
	if !ok {
		t.Fatalf("number has type %T, want object", decoded["number"])
	}
	if number["valid"] != true {
		t.Fatalf("number.valid = %v, want true", number["valid"])
	}
	results, ok := decoded["results"].([]any)
	if !ok || len(results) != 6 {
		t.Fatalf("results = %T len %d, want six module results", decoded["results"], len(results))
	}
}
