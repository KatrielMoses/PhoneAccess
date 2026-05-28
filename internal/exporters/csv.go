package exporters

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

var csvHeader = []string{
	"phone_e164",
	"country",
	"region",
	"carrier",
	"line_type",
	"voip",
	"spam_score",
	"spam_caller_type",
	"spam_report_count",
	"breach_count",
	"stealer_count",
	"enumerator_hit_count",
	"breach_names",
	"data_classes",
	"name_hint",
	"name_confidence",
	"location_hint",
	"likely_ported",
	"local_time",
	"risk_score",
	"risk_band",
	"risk_drivers",
	"risk_summary",
	"run_timestamp",
}

type CSVExporter struct {
	WriteHeader bool
}

func NewCSVExporter() CSVExporter {
	return CSVExporter{WriteHeader: true}
}

func (CSVExporter) Format() string {
	return "csv"
}

func (e CSVExporter) Export(report *core.InvestigationReport, w io.Writer) error {
	return e.ExportAppend(report, w, false)
}

func (e CSVExporter) ExportAppend(report *core.InvestigationReport, w io.Writer, appendMode bool) error {
	if report == nil {
		return errors.New("export csv: report is nil")
	}
	if w == nil {
		return errors.New("export csv: writer is nil")
	}

	writer := csv.NewWriter(w)
	if e.WriteHeader && !appendMode {
		if err := writer.Write(csvHeader); err != nil {
			return fmt.Errorf("write csv header: %w", err)
		}
	}
	if err := writer.Write(flattenReport(report)); err != nil {
		return fmt.Errorf("write csv row: %w", err)
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("flush csv: %w", err)
	}
	return nil
}

func flattenReport(report *core.InvestigationReport) []string {
	number := report.Number
	phone, country, region, lineType, carrier := "", "", "", "", ""
	if number != nil {
		phone = number.E164
		country = number.CountryAlpha2
		region = number.RegionDescription
		lineType = string(number.LineType)
		carrier = number.CarrierHint
	}

	carrier = firstNonEmpty(finding(report, "carrier", "carrier"), carrier)
	lineType = firstNonEmpty(finding(report, "carrier", "line_type"), finding(report, "voip", "line_type"), lineType)
	country = firstNonEmpty(finding(report, "carrier", "country"), country)
	region = firstNonEmpty(finding(report, "carrier", "region"), region)

	voip := firstNonEmpty(finding(report, "voip", "is_voip"), finding(report, "carrier", "voip_suspected"))
	spamScore := firstNonEmpty(finding(report, "spam", "spam_score"), "0")
	spamCallerType := finding(report, "spam", "caller_type")
	spamReportCount := firstNonEmpty(finding(report, "spam", "total_reports"), "0")
	breachCount := firstNonEmpty(finding(report, "breach", "breach_count"), "0")
	stealerCount := firstNonEmpty(finding(report, "breach", "stealer_count"), "0")
	enumeratorHitCount := firstNonEmpty(finding(report, "enumerator", "hit_count"), "0")
	nameHint := finding(report, "reverse", "name_hint")
	nameConfidence := finding(report, "reverse", "name_confidence")
	locationHint := finding(report, "reverse", "location_hint")
	likelyPorted := finding(report, "geo", "likely_ported")
	localTime := finding(report, "geo", "local_time")
	riskScore := reportRiskScore(report)

	return []string{
		phone,
		country,
		region,
		carrier,
		lineType,
		voip,
		spamScore,
		spamCallerType,
		spamReportCount,
		breachCount,
		stealerCount,
		enumeratorHitCount,
		pipeJoin(breachNames(report)),
		pipeJoin(dataClasses(report)),
		nameHint,
		nameConfidence,
		locationHint,
		likelyPorted,
		localTime,
		strconv.Itoa(riskScore.Score),
		string(riskScore.Band),
		formatRiskDrivers(riskScore.Drivers),
		riskScore.Summary,
		report.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
}

func breachNames(report *core.InvestigationReport) []string {
	result := moduleResult(report, "breach")
	if result == nil {
		return nil
	}
	values := stringsFromData(result.Data, "name")
	if len(values) > 0 {
		return values
	}
	lines := splitMulti(finding(report, "breach", "breaches"))
	names := make([]string, 0, len(lines))
	for _, line := range lines {
		if idx := strings.Index(line, " ["); idx >= 0 {
			line = line[:idx]
		}
		names = append(names, strings.TrimSpace(line))
	}
	return uniqueSorted(names)
}

func dataClasses(report *core.InvestigationReport) []string {
	result := moduleResult(report, "breach")
	if result == nil {
		return nil
	}
	values := stringsFromData(result.Data, "data_classes_seen", "data_classes_exposed", "data_classes")
	if len(values) > 0 {
		return values
	}
	return uniqueSorted(splitMulti(finding(report, "breach", "data_classes_seen")))
}

func stringsFromData(data any, keys ...string) []string {
	if data == nil {
		return nil
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return nil
	}
	var decoded any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil
	}
	keySet := map[string]bool{}
	for _, key := range keys {
		keySet[key] = true
	}
	values := []string{}
	walkJSON(decoded, func(key string, value any) {
		if !keySet[key] {
			return
		}
		switch v := value.(type) {
		case string:
			values = append(values, splitMulti(v)...)
		case []any:
			for _, item := range v {
				if text, ok := item.(string); ok {
					values = append(values, text)
				}
			}
		}
	})
	return uniqueSorted(values)
}

func walkJSON(value any, visit func(string, any)) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			visit(key, child)
			walkJSON(child, visit)
		}
	case []any:
		for _, child := range v {
			walkJSON(child, visit)
		}
	}
}

func splitMulti(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == '\n' || r == ',' || r == ';' || r == '|'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" && !strings.EqualFold(part, "unknown") {
			out = append(out, part)
		}
	}
	return out
}

func pipeJoin(values []string) string {
	return strings.Join(uniqueSorted(values), "|")
}

func uniqueSorted(values []string) []string {
	seen := map[string]string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || strings.EqualFold(value, "unknown") {
			continue
		}
		seen[strings.ToLower(value)] = value
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, seen[key])
	}
	return out
}

func atoi(value string) int {
	i, _ := strconv.Atoi(strings.TrimSpace(value))
	return i
}
