package exporters

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
)

func TestCSVExporterFlatRow(t *testing.T) {
	var buf bytes.Buffer
	if err := NewCSVExporter().Export(sampleReport(), &buf); err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	records, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatalf("csv parse error: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("record count = %d, want header and row", len(records))
	}
	if len(records[0]) != len(csvHeader) || len(records[1]) != len(csvHeader) {
		t.Fatalf("column count header=%d row=%d want %d", len(records[0]), len(records[1]), len(csvHeader))
	}

	row := map[string]string{}
	for i, name := range records[0] {
		row[name] = records[1][i]
	}
	if row["phone_e164"] != "+14155552671" {
		t.Fatalf("phone_e164 = %q", row["phone_e164"])
	}
	if row["breach_names"] != "ExampleBreach|OtherBreach" {
		t.Fatalf("breach_names = %q, want pipe-delimited names", row["breach_names"])
	}
	if row["data_classes"] != "email|password|phone" {
		t.Fatalf("data_classes = %q, want pipe-delimited classes", row["data_classes"])
	}
	if strings.Contains(row["breach_names"], ",") {
		t.Fatalf("breach_names should use pipe delimiter, got %q", row["breach_names"])
	}
}

func TestCSVExporterAppendModeWritesSingleHeader(t *testing.T) {
	var buf bytes.Buffer
	exporter := NewCSVExporter()
	if err := exporter.ExportAppend(sampleReport(), &buf, false); err != nil {
		t.Fatalf("first ExportAppend() error = %v", err)
	}
	if err := exporter.ExportAppend(sampleReport(), &buf, true); err != nil {
		t.Fatalf("second ExportAppend() error = %v", err)
	}

	records, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatalf("csv parse error: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("record count = %d, want one header and two rows", len(records))
	}
	headerCount := 0
	for _, record := range records {
		if len(record) > 0 && record[0] == "phone_e164" {
			headerCount++
		}
	}
	if headerCount != 1 {
		t.Fatalf("header count = %d, want 1", headerCount)
	}
}
