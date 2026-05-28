package spam

import (
	"net/url"
	"strings"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

type eightHundredNotesSource struct{}

func (eightHundredNotesSource) Name() string {
	return "800notes"
}

func (eightHundredNotesSource) URL(number *core.PhoneNumber) string {
	return "https://800notes.com/Phone.aspx/" + pathEscape(dashedNational(number))
}

func (eightHundredNotesSource) Parse(body []byte) SourceResult {
	return parseHTMLSource(body)
}

type whoCalledUsSource struct{}

func (whoCalledUsSource) Name() string {
	return "whocalledus"
}

func (whoCalledUsSource) URL(number *core.PhoneNumber) string {
	return "https://whocalledus.com/calls/" + pathEscape(nationalDigits(number)) + "/"
}

func (whoCalledUsSource) Parse(body []byte) SourceResult {
	return parseHTMLSource(body)
}

type spamCallsSource struct{}

func (spamCallsSource) Name() string {
	return "spamcalls"
}

func (spamCallsSource) URL(number *core.PhoneNumber) string {
	endpoint, _ := url.Parse("https://www.spamcalls.net/en/search")
	query := endpoint.Query()
	query.Set("number", internationalDigits(number))
	endpoint.RawQuery = query.Encode()
	return endpoint.String()
}

func (spamCallsSource) Parse(body []byte) SourceResult {
	return parseHTMLSource(body)
}

func dashedNational(number *core.PhoneNumber) string {
	digits := nationalDigits(number)
	if len(digits) == 10 {
		return digits[:3] + "-" + digits[3:6] + "-" + digits[6:]
	}
	return digits
}

func nationalDigits(number *core.PhoneNumber) string {
	if number == nil {
		return ""
	}
	if digits := onlyDigits(number.NationalNumber); digits != "" {
		return digits
	}
	digits := onlyDigits(firstNonEmpty(number.E164, number.RawInput))
	if number.CountryCode == 1 && len(digits) == 11 && strings.HasPrefix(digits, "1") {
		return digits[1:]
	}
	return digits
}

func internationalDigits(number *core.PhoneNumber) string {
	if number == nil {
		return ""
	}
	if digits := onlyDigits(number.E164); digits != "" {
		return digits
	}
	digits := onlyDigits(number.RawInput)
	if digits != "" {
		return digits
	}
	return nationalDigits(number)
}

func pathEscape(value string) string {
	return url.PathEscape(strings.TrimSpace(value))
}
