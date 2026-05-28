package core

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/nyaruka/phonenumbers"
)

const defaultRegion = "US"

type InvalidPhoneNumberError struct {
	Raw    string
	Reason string
	Err    error
}

func (e *InvalidPhoneNumberError) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("invalid phone number %q", e.Raw)
	}
	return fmt.Sprintf("invalid phone number %q: %s", e.Raw, e.Reason)
}

func (e *InvalidPhoneNumberError) Unwrap() error {
	return e.Err
}

func NormalizePhoneNumber(raw string) (*PhoneNumber, error) {
	input := strings.TrimSpace(raw)
	if input == "" {
		return nil, &InvalidPhoneNumberError{Raw: raw, Reason: "phone number cannot be empty"}
	}

	parsed, err := phonenumbers.Parse(input, defaultRegion)
	if err != nil {
		return nil, &InvalidPhoneNumberError{
			Raw:    raw,
			Reason: "the value could not be parsed as a phone number",
			Err:    err,
		}
	}

	if !phonenumbers.IsValidNumber(parsed) {
		return nil, &InvalidPhoneNumberError{
			Raw:    raw,
			Reason: "the number is not valid for its country or numbering plan",
		}
	}

	region := phonenumbers.GetRegionCodeForNumber(parsed)
	description, _ := phonenumbers.GetGeocodingForNumber(parsed, "en")
	carrier, _ := phonenumbers.GetSafeCarrierDisplayNameForNumber(parsed, "en")
	timezones, _ := phonenumbers.GetTimezonesForNumber(parsed)

	return &PhoneNumber{
		RawInput:          raw,
		E164:              phonenumbers.Format(parsed, phonenumbers.E164),
		SearchVariants:    numberVariants(parsed),
		CountryCode:       int(parsed.GetCountryCode()),
		CountryAlpha2:     region,
		NationalNumber:    strconv.FormatUint(parsed.GetNationalNumber(), 10),
		RegionDescription: fallback(description, region),
		LineType:          mapLineType(phonenumbers.GetNumberType(parsed)),
		CarrierHint:       carrier,
		Timezone:          fallback(strings.Join(timezones, ", "), "unknown"),
		Valid:             true,
	}, nil
}

func IsInvalidPhoneNumber(err error) bool {
	var target *InvalidPhoneNumberError
	return errors.As(err, &target)
}

func fallback(value, fallbackValue string) string {
	if strings.TrimSpace(value) == "" {
		return fallbackValue
	}
	return value
}

func mapLineType(kind phonenumbers.PhoneNumberType) LineType {
	switch kind {
	case phonenumbers.MOBILE:
		return LineTypeMobile
	case phonenumbers.FIXED_LINE_OR_MOBILE:
		return LineTypeMobile
	case phonenumbers.FIXED_LINE:
		return LineTypeLandline
	case phonenumbers.VOIP:
		return LineTypeVoIP
	case phonenumbers.TOLL_FREE:
		return LineTypeTollFree
	case phonenumbers.PREMIUM_RATE:
		return LineTypePremiumRate
	default:
		return LineTypeUnknown
	}
}

func SearchVariantsFor(number *PhoneNumber) []string {
	if number == nil {
		return nil
	}
	if len(number.SearchVariants) > 0 {
		return uniqueStrings(number.SearchVariants)
	}
	return uniqueStrings([]string{
		number.E164,
		number.NationalNumber,
	})
}

func SearchQueryPhrase(number *PhoneNumber) string {
	variants := SearchVariantsFor(number)
	if len(variants) == 0 {
		return `""`
	}
	parts := make([]string, 0, len(variants))
	for _, variant := range variants {
		escaped := strings.ReplaceAll(variant, `"`, `\"`)
		parts = append(parts, `"`+escaped+`"`)
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

func numberVariants(parsed *phonenumbers.PhoneNumber) []string {
	if parsed == nil {
		return nil
	}
	digits := strconv.FormatUint(parsed.GetNationalNumber(), 10)
	e164 := phonenumbers.Format(parsed, phonenumbers.E164)
	national := phonenumbers.Format(parsed, phonenumbers.NATIONAL)
	international := phonenumbers.Format(parsed, phonenumbers.INTERNATIONAL)
	compactNational := onlyDigits(national)
	if compactNational == "" {
		compactNational = digits
	}
	if len(compactNational) > 10 {
		compactNational = compactNational[len(compactNational)-10:]
	}
	parts := splitPhoneDigits(compactNational)
	hyphenated := strings.Join(parts, "-")
	spaced := strings.Join(parts, " ")
	dotted := strings.Join(parts, ".")
	parenLocal := ""
	if len(parts) == 3 {
		parenLocal = fmt.Sprintf("(%s) %s-%s", parts[0], parts[1], parts[2])
	}
	variants := []string{
		e164,
		digits,
		spaced,
		hyphenated,
		dotted,
	}
	if parenLocal != "" {
		variants = append(variants, parenLocal)
	} else if strings.TrimSpace(national) != "" {
		variants = append(variants, national)
	} else {
		variants = append(variants, international)
	}
	return uniqueStrings(variants)
}

func splitPhoneDigits(value string) []string {
	digits := onlyDigits(value)
	switch {
	case len(digits) >= 10:
		digits = digits[len(digits)-10:]
		return []string{digits[:3], digits[3:6], digits[6:10]}
	case len(digits) > 6:
		return []string{digits[:3], digits[3:6], digits[6:]}
	case len(digits) > 3:
		return []string{digits[:3], digits[3:]}
	case len(digits) > 0:
		return []string{digits}
	default:
		return nil
	}
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

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	return out
}
