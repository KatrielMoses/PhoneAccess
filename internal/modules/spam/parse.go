package spam

import (
	"html"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

var (
	scriptStyleRE = regexp.MustCompile(`(?is)<(?:script|style)[^>]*>.*?</(?:script|style)>`)
	tagRE         = regexp.MustCompile(`(?is)<[^>]+>`)
	spaceRE       = regexp.MustCompile(`\s+`)
	commentRE     = regexp.MustCompile(`(?is)<(?:div|p|td|li|blockquote)[^>]*(?:class|id)\s*=\s*["'][^"']*(?:comment|message|report|post|entry|complaint)[^"']*["'][^>]*>(.*?)</(?:div|p|td|li|blockquote)>`)
	blockquoteRE  = regexp.MustCompile(`(?is)<blockquote[^>]*>(.*?)</blockquote>`)
	countREs      = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(\d{1,6})\s+(?:user\s+)?(?:reports?|comments?|complaints?)\b`),
		regexp.MustCompile(`(?i)(?:reports?|comments?|complaints?)\s*[:(]?\s*(\d{1,6})\b`),
		regexp.MustCompile(`(?i)reported\s+(\d{1,6})\s+times\b`),
	}
	typeLabelRE = regexp.MustCompile(`(?i)(?:caller\s*type|call\s*type|type)\s*[:\-]?\s*([a-z][a-z\s-]{2,40})`)
	isoDateRE   = regexp.MustCompile(`\b(20\d{2}-\d{1,2}-\d{1,2})\b`)
	usDateRE    = regexp.MustCompile(`\b(\d{1,2}/\d{1,2}/20\d{2})\b`)
	monthDateRE = regexp.MustCompile(`(?i)\b((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},\s+20\d{2})\b`)
)

func parseHTMLSource(body []byte) SourceResult {
	raw := string(body)
	text := cleanHTML(raw)
	snippets := extractCommentSnippets(raw)
	reports := extractReportCount(text)
	if reports == 0 && len(snippets) > 0 {
		reports = len(snippets)
	}

	return SourceResult{
		Reports:    reports,
		CallerType: extractCallerType(text),
		Snippets:   snippets,
		MostRecent: extractMostRecentDate(text),
	}
}

func extractReportCount(text string) int {
	if isNoResultText(text) {
		return 0
	}
	best := 0
	for _, re := range countREs {
		for _, match := range re.FindAllStringSubmatch(text, -1) {
			if len(match) < 2 {
				continue
			}
			value, err := strconv.Atoi(strings.ReplaceAll(match[1], ",", ""))
			if err == nil && value > best {
				best = value
			}
		}
	}
	return best
}

func extractCallerType(text string) string {
	for _, match := range typeLabelRE.FindAllStringSubmatch(text, -1) {
		if len(match) < 2 {
			continue
		}
		if callerType := normalizeCallerType(match[1]); callerType != "unknown" {
			return callerType
		}
	}
	// Do not fall back to scanning the full page text: keywords like "robocall"
	// appear in site navigation and filter UI, producing false positives when
	// there are zero reports or snippets for the number.
	return ""
}

func normalizeCallerType(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, "_", " ")
	normalized = strings.ReplaceAll(normalized, "-", " ")
	normalized = spaceRE.ReplaceAllString(normalized, " ")

	switch {
	case strings.Contains(normalized, "fraud"):
		return "fraudster"
	case strings.Contains(normalized, "scam"):
		return "scammer"
	case strings.Contains(normalized, "debt") || strings.Contains(normalized, "collection"):
		return "debt collector"
	case strings.Contains(normalized, "robo") || strings.Contains(normalized, "automated"):
		return "robocall"
	case strings.Contains(normalized, "telemarket") || strings.Contains(normalized, "sales"):
		return "telemarketer"
	default:
		return "unknown"
	}
}

func extractCommentSnippets(raw string) []string {
	candidates := make([]string, 0)
	for _, re := range []*regexp.Regexp{commentRE, blockquoteRE} {
		for _, match := range re.FindAllStringSubmatch(raw, -1) {
			if len(match) < 2 {
				continue
			}
			if snippet := normalizeSnippet(cleanHTML(match[1])); snippet != "" {
				candidates = append(candidates, snippet)
			}
		}
	}
	return selectSnippets(candidates, 3)
}

func selectSnippets(snippets []string, limit int) []string {
	if limit <= 0 || len(snippets) == 0 {
		return nil
	}
	seen := map[string]bool{}
	deduped := make([]string, 0, len(snippets))
	for _, snippet := range snippets {
		normalized := normalizeSnippet(snippet)
		if normalized == "" {
			continue
		}
		key := strings.ToLower(normalized)
		if seen[key] {
			continue
		}
		seen[key] = true
		deduped = append(deduped, normalized)
	}
	sort.SliceStable(deduped, func(i, j int) bool {
		return len(deduped[i]) > len(deduped[j])
	})
	if len(deduped) > limit {
		return deduped[:limit]
	}
	return deduped
}

func normalizeSnippet(value string) string {
	value = strings.TrimSpace(value)
	value = spaceRE.ReplaceAllString(value, " ")
	if len(value) < 20 {
		return ""
	}
	lower := strings.ToLower(value)
	if strings.Contains(lower, "javascript") || strings.Contains(lower, "cookie") {
		return ""
	}
	if len(value) > 280 {
		value = strings.TrimSpace(value[:280]) + "..."
	}
	return value
}

func extractMostRecentDate(text string) *time.Time {
	var newest *time.Time
	for _, candidate := range dateCandidates(text) {
		if parsed, ok := parseDate(candidate); ok {
			if newest == nil || parsed.After(*newest) {
				copyTime := parsed
				newest = &copyTime
			}
		}
	}
	return newest
}

func dateCandidates(text string) []string {
	candidates := make([]string, 0)
	for _, re := range []*regexp.Regexp{isoDateRE, usDateRE, monthDateRE} {
		for _, match := range re.FindAllStringSubmatch(text, -1) {
			if len(match) > 1 {
				candidates = append(candidates, match[1])
			}
		}
	}
	return candidates
}

func parseDate(value string) (time.Time, bool) {
	value = strings.TrimSpace(strings.ReplaceAll(value, ".", ""))
	for _, layout := range []string{"2006-1-2", "1/2/2006", "01/02/2006", "Jan 2, 2006", "January 2, 2006"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func cleanHTML(value string) string {
	value = scriptStyleRE.ReplaceAllString(value, " ")
	value = strings.ReplaceAll(value, "<br>", " ")
	value = strings.ReplaceAll(value, "<br/>", " ")
	value = strings.ReplaceAll(value, "<br />", " ")
	value = tagRE.ReplaceAllString(value, " ")
	value = html.UnescapeString(value)
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return ' '
		}
		return r
	}, value)
	return strings.TrimSpace(spaceRE.ReplaceAllString(value, " "))
}

func isNoResultText(text string) bool {
	text = strings.ToLower(text)
	return strings.Contains(text, "no reports") ||
		strings.Contains(text, "no complaints") ||
		strings.Contains(text, "no results") ||
		strings.Contains(text, "nothing found")
}

func onlyDigits(value string) string {
	var builder strings.Builder
	for _, r := range value {
		if r >= '0' && r <= '9' {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
