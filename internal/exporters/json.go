package exporters

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

type JSONExporter struct{}

func (JSONExporter) Format() string {
	return "json"
}

func (JSONExporter) Export(report *core.InvestigationReport, w io.Writer) error {
	if report == nil {
		return errors.New("export json: report is nil")
	}
	if w == nil {
		return errors.New("export json: writer is nil")
	}

	data, err := marshalReportJSON(report)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func marshalReportJSON(report *core.InvestigationReport) ([]byte, error) {
	encoded, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("encode json: %w", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &raw); err != nil {
		return nil, fmt.Errorf("normalize json: %w", err)
	}

	timestamp, err := json.Marshal(report.GeneratedAt.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("encode timestamp: %w", err)
	}
	raw["generated_at"] = timestamp

	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("indent json: %w", err)
	}
	return append(out, '\n'), nil
}
