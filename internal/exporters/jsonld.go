package exporters

import (
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"sort"
	"strings"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

type JSONLDExporter struct{}

func (JSONLDExporter) Format() string {
	return "jsonld"
}

func (JSONLDExporter) Export(report *core.InvestigationReport, w io.Writer) error {
	if report == nil {
		return errors.New("export jsonld: report is nil")
	}
	if w == nil {
		return errors.New("export jsonld: writer is nil")
	}

	payload := map[string]any{
		"@context": "https://schema.org",
		"@type":    "Person",
	}

	if phone := reportPhone(report); phone != "" {
		payload["telephone"] = phone
	}
	if name := topNameCandidate(report); name != "" {
		payload["name"] = name
	}
	if emails := discoveredEmails(report); len(emails) > 0 {
		payload["email"] = emails
	}
	if urls := verifiedPlatformURLs(report); len(urls) > 0 {
		payload["sameAs"] = urls
	}
	if orgs := organizationNames(report); len(orgs) > 0 {
		memberOf := make([]map[string]any, 0, len(orgs))
		for _, org := range orgs {
			memberOf = append(memberOf, map[string]any{
				"@type": "Organization",
				"name":  org,
			})
		}
		payload["memberOf"] = memberOf
	}

	risk := reportRiskScore(report)
	if risk != nil {
		payload["knowsAbout"] = string(risk.Band)
		payload["identifier"] = []map[string]any{
			{"@type": "PropertyValue", "name": "risk_score", "value": risk.Score},
			{"@type": "PropertyValue", "name": "breach_count", "value": breachCount(report)},
		}
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}

func reportPhone(report *core.InvestigationReport) string {
	if report == nil || report.Number == nil {
		return ""
	}
	return firstNonEmpty(report.Number.E164, report.Number.RawInput)
}

func topNameCandidate(report *core.InvestigationReport) string {
	if report == nil || report.IdentityGraph == nil {
		return ""
	}
	for _, pivot := range report.IdentityGraph.PivotPoints {
		if strings.EqualFold(pivot.Type, "name") && strings.TrimSpace(pivot.Value) != "" {
			return strings.TrimSpace(pivot.Value)
		}
	}
	return ""
}

func discoveredEmails(report *core.InvestigationReport) []string {
	seen := map[string]string{}
	if report != nil && report.IdentityGraph != nil {
		for _, pivot := range report.IdentityGraph.PivotPoints {
			if !strings.EqualFold(pivot.Type, "email") {
				continue
			}
			value := strings.TrimSpace(pivot.Value)
			if value != "" {
				seen[strings.ToLower(value)] = value
			}
		}
	}
	out := make([]string, 0, len(seen))
	for _, value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func verifiedPlatformURLs(report *core.InvestigationReport) []string {
	seen := map[string]string{}
	var walk func(*core.PivotChainNode)
	walk = func(node *core.PivotChainNode) {
		if node == nil {
			return
		}
		if strings.EqualFold(node.Type, "platform") && strings.TrimSpace(node.URL) != "" {
			seen[strings.ToLower(strings.TrimSpace(node.URL))] = strings.TrimSpace(node.URL)
		}
		for _, child := range node.Children {
			walk(child)
		}
	}
	walk(report.PivotChain)
	out := make([]string, 0, len(seen))
	for _, value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func breachCount(report *core.InvestigationReport) int {
	result := moduleResult(report, "breach")
	if result == nil || result.Findings == nil {
		return 0
	}
	if value := strings.TrimSpace(result.Findings["breach_count"]); value != "" {
		if count, err := strconv.Atoi(value); err == nil {
			return count
		}
	}
	var decoded struct {
		Breaches []any `json:"breaches"`
	}
	if result.Data != nil {
		if raw, err := json.Marshal(result.Data); err == nil {
			_ = json.Unmarshal(raw, &decoded)
		}
	}
	if len(decoded.Breaches) > 0 {
		return len(decoded.Breaches)
	}
	return 0
}
