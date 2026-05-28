package exporters

import (
	"bytes"
	"strings"
	"testing"
)

func TestTextExporterPlainOutput(t *testing.T) {
	var buf bytes.Buffer
	if err := NewTextExporter(nil).Export(sampleReport(), &buf); err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	out := buf.String()
	for _, header := range []string{"NUMBER INTELLIGENCE", "SPAM & REPUTATION", "BREACH INTELLIGENCE", "IDENTITY GRAPH"} {
		if !strings.Contains(out, header) {
			t.Fatalf("output missing header %q", header)
		}
	}
	if ansiPattern.MatchString(out) {
		t.Fatalf("output contains ANSI escapes: %q", out)
	}
}

func TestStripANSI(t *testing.T) {
	got := StripANSI("\x1b[31mNUMBER INTELLIGENCE\x1b[0m")
	if got != "NUMBER INTELLIGENCE" {
		t.Fatalf("StripANSI() = %q", got)
	}
}
