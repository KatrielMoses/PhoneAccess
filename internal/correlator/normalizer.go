package correlator

import (
	"regexp"
	"strings"
	"time"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

var (
	spacePattern     = regexp.MustCompile(`\s+`)
	punctuationRE    = regexp.MustCompile(`[.,;:]+`)
	zipPattern       = regexp.MustCompile(`\b\d{5}(?:-\d{4})?\b`)
	pinPattern       = regexp.MustCompile(`\b\d{6}\b`)
	ukPostcodeRE     = regexp.MustCompile(`(?i)\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b`)
	honorifics       = map[string]bool{"mr": true, "mrs": true, "ms": true, "miss": true, "dr": true, "sri": true, "shri": true}
	monthYearPattern = regexp.MustCompile(`(?i)\b(0?[1-9]|1[0-2])[/\-](\d{4})\b`)
)

func NormalizeValue(field, value string) (string, string) {
	switch field {
	case FieldName:
		return NormalizeName(value), ""
	case FieldAddress, FieldRegion:
		return NormalizeAddress(value), ""
	case FieldDOB:
		return NormalizeDOB(value)
	case FieldEmail:
		return strings.ToLower(strings.TrimSpace(value)), ""
	case FieldSocialLink:
		return strings.ToLower(strings.TrimSpace(value)), ""
	default:
		return normalizeText(value), ""
	}
}

func NormalizeName(value string) string {
	value = normalizeText(value)
	value = strings.ReplaceAll(value, ".", "")
	parts := strings.Fields(value)
	out := parts[:0]
	for _, part := range parts {
		if !honorifics[part] {
			out = append(out, part)
		}
	}
	return strings.Join(out, " ")
}

func NormalizeAddress(value string) string {
	value = normalizeText(value)
	value = punctuationRE.ReplaceAllString(value, " ")
	value = strings.ReplaceAll(value, "#", " ")
	value = expandStreetWords(value)
	return strings.Join(strings.Fields(value), " ")
}

func NormalizeDOB(value string) (string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	for _, layout := range []string{"2006-01-02", "02-01-2006", "01/02/2006", "02/01/2006"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.Format("2006-01-02"), "full"
		}
	}
	if parsed, err := time.Parse("2006-01", value); err == nil {
		return parsed.Format("2006-01"), "month"
	}
	if match := monthYearPattern.FindStringSubmatch(value); len(match) == 3 {
		return match[2] + "-" + leftPad2(match[1]), "month"
	}
	if len(value) == 4 && value[0] >= '0' && value[0] <= '9' {
		return value, "year"
	}
	return normalizeText(value), ""
}

func normalizeText(value string) string {
	value = norm.NFKC.String(strings.TrimSpace(value))
	value = stripDiacritics(value)
	value = strings.ToLower(value)
	value = strings.Trim(value, `"'[]()<>`)
	return spacePattern.ReplaceAllString(value, " ")
}

func stripDiacritics(value string) string {
	decomposed := norm.NFD.String(value)
	var builder strings.Builder
	for _, r := range decomposed {
		if unicode.Is(unicode.Mn, r) {
			continue
		}
		builder.WriteRune(r)
	}
	return norm.NFC.String(builder.String())
}

func expandStreetWords(value string) string {
	replacer := strings.NewReplacer(
		" st ", " street ",
		" rd ", " road ",
		" ave ", " avenue ",
		" blvd ", " boulevard ",
		" ln ", " lane ",
		" apt ", " apartment ",
	)
	replaced := replacer.Replace(" " + value + " ")
	return strings.TrimSpace(replaced)
}

func postcode(value string) string {
	value = strings.ToUpper(value)
	if match := ukPostcodeRE.FindString(value); match != "" {
		return strings.ReplaceAll(match, " ", "")
	}
	if match := pinPattern.FindString(value); match != "" {
		return match
	}
	if match := zipPattern.FindString(value); match != "" {
		return strings.Split(match, "-")[0]
	}
	return ""
}

func leftPad2(value string) string {
	if len(value) == 1 {
		return "0" + value
	}
	return value
}
