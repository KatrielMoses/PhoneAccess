package exporters

import (
	"bytes"
	"testing"
)

func TestPDFExporterGeneratesBytes(t *testing.T) {
	var buf bytes.Buffer
	if err := (PDFExporter{}).Export(sampleReport(), &buf); err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("pdf output is empty")
	}
	if got := buf.String()[:4]; got != "%PDF" {
		t.Fatalf("pdf header = %q, want %%PDF", got)
	}
}
