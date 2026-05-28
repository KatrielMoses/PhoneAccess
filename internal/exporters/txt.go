package exporters

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

type TextExporter struct {
	Render func(*core.InvestigationReport) string
}

func NewTextExporter(render func(*core.InvestigationReport) string) TextExporter {
	return TextExporter{Render: render}
}

func (TextExporter) Format() string {
	return "txt"
}

func (e TextExporter) Export(report *core.InvestigationReport, w io.Writer) error {
	if report == nil {
		return errors.New("export txt: report is nil")
	}
	if w == nil {
		return errors.New("export txt: writer is nil")
	}

	output := ""
	if e.Render != nil {
		output = e.Render(report)
	} else {
		output = renderPlainReport(report)
	}
	output = StripANSI(output)
	if !strings.HasSuffix(output, "\n") {
		output += "\n"
	}
	_, err := io.WriteString(w, output)
	return err
}

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

func StripANSI(value string) string {
	return ansiPattern.ReplaceAllString(value, "")
}

func renderPlainReport(report *core.InvestigationReport) string {
	sections := []string{
		"PhoneAccess",
		plainNumberSection(report),
		plainModuleSection(report, "carrier", "CARRIER INTELLIGENCE"),
		plainModuleSection(report, "spam", "SPAM & REPUTATION"),
		plainModuleSection(report, "breach", "BREACH INTELLIGENCE"),
		plainModuleSection(report, "reverse", "REVERSE LOOKUP"),
		plainIdentityGraph(report),
		plainModuleSection(report, "voip", "VOIP INTELLIGENCE"),
		plainModuleSection(report, "geo", "GEOGRAPHIC INTELLIGENCE"),
		plainRiskSection(report),
	}
	return strings.Join(sections, "\n\n")
}

func plainNumberSection(report *core.InvestigationReport) string {
	lines := []string{"NUMBER INTELLIGENCE"}
	if report.Number == nil {
		return strings.Join(append(lines, plainRow("Status", "not available")), "\n")
	}
	number := report.Number
	rows := [][2]string{
		{"Raw input", number.RawInput},
		{"Normalized", number.E164},
		{"Valid", fmt.Sprintf("%t", number.Valid)},
		{"Country", fmt.Sprintf("+%d (%s)", number.CountryCode, number.CountryAlpha2)},
		{"National number", number.NationalNumber},
		{"Region", number.RegionDescription},
		{"Line type", string(number.LineType)},
		{"Carrier hint", empty(number.CarrierHint)},
		{"Timezone", number.Timezone},
	}
	for _, row := range rows {
		lines = append(lines, plainRow(row[0], row[1]))
	}
	return strings.Join(lines, "\n")
}

func plainModuleSection(report *core.InvestigationReport, moduleName, title string) string {
	lines := []string{title}
	result := moduleResult(report, moduleName)
	if result == nil || len(result.Findings) == 0 {
		return strings.Join(append(lines, plainRow("Status", "not available")), "\n")
	}
	lines = append(lines, plainRow("Status", string(result.Status)))
	keys := make([]string, 0, len(result.Findings))
	for key := range result.Findings {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if strings.TrimSpace(result.Findings[key]) != "" {
			lines = append(lines, plainRow(humanize(key), result.Findings[key]))
		}
	}
	for _, evidence := range result.Evidence {
		if strings.TrimSpace(evidence) != "" {
			lines = append(lines, "  Evidence: "+strings.TrimSpace(evidence))
		}
	}
	return strings.Join(lines, "\n")
}

func plainIdentityGraph(report *core.InvestigationReport) string {
	lines := []string{"IDENTITY GRAPH"}
	if report.IdentityGraph == nil || len(report.IdentityGraph.PivotPoints) == 0 {
		return strings.Join(append(lines, plainRow("Pivots", "none discovered")), "\n")
	}
	for _, pivot := range report.IdentityGraph.PivotPoints {
		lines = append(lines, fmt.Sprintf("- %s: %s %s (%s)", pivot.Type, pivot.Value, pivot.Confidence, strings.Join(pivot.Modules, ", ")))
	}
	if len(report.IdentityGraph.SuggestedCommands) > 0 {
		lines = append(lines, "")
		lines = append(lines, report.IdentityGraph.SuggestedCommands...)
	}
	return strings.Join(lines, "\n")
}

func plainRiskSection(report *core.InvestigationReport) string {
	risk := reportRiskScore(report)
	lines := []string{"RISK SCORE"}
	lines = append(lines, plainRow("Score", fmt.Sprintf("%d/100", risk.Score)))
	lines = append(lines, plainRow("Band", string(risk.Band)))
	lines = append(lines, plainRow("Summary", risk.Summary))
	if len(risk.Drivers) > 0 {
		lines = append(lines, plainRow("Drivers", formatRiskDrivers(risk.Drivers)))
	}
	return strings.Join(lines, "\n")
}

func plainRow(label, value string) string {
	return fmt.Sprintf("%-18s%s", label, value)
}
