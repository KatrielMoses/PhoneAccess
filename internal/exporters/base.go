package exporters

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

type Exporter interface {
	Format() string
	Export(report *core.InvestigationReport, w io.Writer) error
}

type AppendExporter interface {
	ExportAppend(report *core.InvestigationReport, w io.Writer, appendMode bool) error
}

func New(format string) (Exporter, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		return JSONExporter{}, nil
	case "csv":
		return NewCSVExporter(), nil
	case "pdf":
		return PDFExporter{}, nil
	case "txt", "text":
		return NewTextExporter(nil), nil
	case "gexf":
		return GEXFExporter{}, nil
	case "jsonld":
		return JSONLDExporter{}, nil
	default:
		return nil, fmt.Errorf("unsupported export format %q", format)
	}
}

func FormatFromPath(path string) string {
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(path), "."))
	if ext == "text" {
		return "txt"
	}
	return ext
}

func Supported(format string) bool {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json", "csv", "pdf", "txt", "text", "gexf", "jsonld":
		return true
	default:
		return false
	}
}

func moduleResult(report *core.InvestigationReport, name string) *core.ModuleResult {
	if report == nil {
		return nil
	}
	for _, result := range report.Results {
		if result != nil && result.ModuleName == name {
			return result
		}
	}
	return nil
}

func finding(report *core.InvestigationReport, moduleName, key string) string {
	result := moduleResult(report, moduleName)
	if result == nil || result.Findings == nil {
		return ""
	}
	return strings.TrimSpace(result.Findings[key])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func reportRiskScore(report *core.InvestigationReport) *core.RiskScore {
	if report == nil {
		return core.ScoreRisk(nil)
	}
	if report.RiskScore != nil {
		return report.RiskScore
	}
	return core.ScoreRisk(report)
}

func formatRiskDrivers(drivers []core.RiskDriver) string {
	parts := make([]string, 0, len(drivers))
	for _, driver := range drivers {
		parts = append(parts, fmt.Sprintf("%s (%d)", driver.Label, driver.Points))
	}
	return strings.Join(parts, " | ")
}
