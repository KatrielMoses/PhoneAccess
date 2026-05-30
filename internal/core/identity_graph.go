package core

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type IdentityGraph struct {
	PivotPoints       []IdentityPivot `json:"pivot_points"`
	SuggestedCommands []string        `json:"suggested_commands,omitempty"`
}

type IdentityPivot struct {
	Type       string   `json:"type"`
	Value      string   `json:"value"`
	Modules    []string `json:"modules"`
	Confidence string   `json:"confidence"`
}

type pivotAccumulator struct {
	kind    string
	value   string
	modules map[string]bool
}

var (
	graphEmailPattern    = regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`)
	graphUsernamePattern = regexp.MustCompile(`(?i)(?:^|[\s(/])@([A-Z0-9_][A-Z0-9_.]{2,29})\b`)
)

func BuildIdentityGraph(report *InvestigationReport) *IdentityGraph {
	graph := &IdentityGraph{PivotPoints: []IdentityPivot{}}
	if report == nil {
		return graph
	}

	pivots := map[string]*pivotAccumulator{}
	add := func(kind, value, module string) {
		kind = strings.ToLower(strings.TrimSpace(kind))
		value = cleanPivotValue(value)
		if kind == "" || value == "" || module == "" || isUnknownPivot(value) {
			return
		}
		key := kind + ":" + normalizePivot(kind, value)
		if pivots[key] == nil {
			pivots[key] = &pivotAccumulator{kind: kind, value: value, modules: map[string]bool{}}
		}
		pivots[key].modules[module] = true
	}

	for _, result := range report.Results {
		if result == nil {
			continue
		}
		collectFromFindings(result, add)
		collectFromData(result, add)
	}

	graph.PivotPoints = rankPivots(pivots)
	graph.SuggestedCommands = suggestedCommands(graph.PivotPoints)
	return graph
}

func collectFromFindings(result *ModuleResult, add func(string, string, string)) {
	for key, value := range result.Findings {
		kind := kindFromKey(key)
		if kind != "" {
			for _, part := range splitPivotList(value) {
				add(kind, part, result.ModuleName)
			}
		}
		for _, email := range graphEmailPattern.FindAllString(value, -1) {
			add("email", email, result.ModuleName)
		}
		for _, match := range graphUsernamePattern.FindAllStringSubmatch(value, -1) {
			if len(match) > 1 {
				add("username", match[1], result.ModuleName)
			}
		}
	}
}

func collectFromData(result *ModuleResult, add func(string, string, string)) {
	if result.Data == nil {
		return
	}
	data, err := json.Marshal(result.Data)
	if err != nil {
		return
	}
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return
	}
	walkIdentityData(decoded, "", result.ModuleName, add)
}

func walkIdentityData(value any, key, module string, add func(string, string, string)) {
	switch v := value.(type) {
	case map[string]any:
		for childKey, child := range v {
			walkIdentityData(child, childKey, module, add)
		}
	case []any:
		for _, child := range v {
			walkIdentityData(child, key, module, add)
		}
	case string:
		if kind := kindFromKey(key); kind != "" {
			if !(kind == "name" && strings.EqualFold(strings.TrimSpace(key), "name")) {
				for _, part := range splitPivotList(v) {
					add(kind, part, module)
				}
			}
		}
		for _, email := range graphEmailPattern.FindAllString(v, -1) {
			add("email", email, module)
		}
		for _, match := range graphUsernamePattern.FindAllStringSubmatch(v, -1) {
			if len(match) > 1 {
				add("username", match[1], module)
			}
		}
	}
}

func kindFromKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	switch key {
	case "name", "names", "name_hint", "caller_name", "owner", "owner_name", "discovered_names", "venmo_display_name",
		"registrant_names", "registrant_name":
		return "name"
	case "entity_name", "entity_names", "company", "company_name", "company_names", "officer_name", "officer_names", "party_name", "party_names", "licensee_name", "licensee_names", "license_name", "license_names":
		return "name"
	case "email", "emails", "pivot_email", "pivot_emails", "registrant_emails":
		return "email"
	case "username", "usernames", "handle", "handles", "pivot_username", "pivot_usernames", "discovered_usernames", "venmo_username":
		return "username"
	case "url", "urls", "pivot_url", "pivot_urls", "social_link", "social_links":
		return "social_link"
	case "linked_account", "linked_accounts", "account", "accounts", "profile", "profiles":
		return "linked_account"
	case "domain", "domains", "discovered_domains", "pivot_domain", "pivot_domains", "associated_domains":
		return "domain"
	default:
		return ""
	}
}

func rankPivots(pivots map[string]*pivotAccumulator) []IdentityPivot {
	out := make([]IdentityPivot, 0, len(pivots))
	for _, pivot := range pivots {
		modules := make([]string, 0, len(pivot.modules))
		for module := range pivot.modules {
			modules = append(modules, module)
		}
		sort.Strings(modules)
		conf := graphConfidenceForPivot(len(modules), modules)
		if pivot.kind == "domain" {
			conf = domainPivotConfidence(len(modules), modules)
		}
		out = append(out, IdentityPivot{
			Type:       pivot.kind,
			Value:      pivot.value,
			Modules:    modules,
			Confidence: conf,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if len(out[i].Modules) == len(out[j].Modules) {
			if out[i].Type == out[j].Type {
				return strings.ToLower(out[i].Value) < strings.ToLower(out[j].Value)
			}
			return out[i].Type < out[j].Type
		}
		return len(out[i].Modules) > len(out[j].Modules)
	})
	return out
}

func suggestedCommands(pivots []IdentityPivot) []string {
	seen := map[string]bool{}
	commands := make([]string, 0)
	for _, pivot := range pivots {
		if pivot.Type != "email" {
			continue
		}
		command := fmt.Sprintf("mailaccess investigate %s", pivot.Value)
		if !seen[command] {
			seen[command] = true
			commands = append(commands, command)
		}
	}
	return commands
}

func graphConfidence(moduleCount int) string {
	if moduleCount >= 2 {
		return "high"
	}
	return "medium"
}

func graphConfidenceForPivot(moduleCount int, modules []string) string {
	if moduleCount == 1 && len(modules) == 1 {
		switch strings.ToLower(strings.TrimSpace(modules[0])) {
		case "search", "paste":
			return "low"
		case "enumerator", "infrastructure":
			return "inference"
		}
	}
	return graphConfidence(moduleCount)
}

// domainPivotConfidence returns "inference" for all domain pivots regardless of source count.
// Domain association via SSL CT is a weak signal.
func domainPivotConfidence(_ int, _ []string) string {
	return "inference"
}

func splitPivotList(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == ';' || r == '|'
	})
}

func cleanPivotValue(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'[]()<>`)
	return strings.Join(strings.Fields(value), " ")
}

func normalizePivot(kind, value string) string {
	value = strings.ToLower(cleanPivotValue(value))
	if kind == "username" {
		value = strings.TrimPrefix(value, "@")
	}
	return value
}

func isUnknownPivot(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "unknown", "none", "not available", "skipped", "true", "false":
		return true
	default:
		return false
	}
}
