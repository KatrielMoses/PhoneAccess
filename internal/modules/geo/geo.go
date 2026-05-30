package geo

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

const moduleName = "geo"

//go:embed data/areacodes.json data/high_risk_regions.json
var dataFS embed.FS

type Module struct {
	now       func() time.Time
	areaCodes map[string]areaCodeRecord
	risk      riskDataset
}

type Option func(*Module)

type Result struct {
	AreaCodeOrigin       string         `json:"area_code_origin"`
	AreaCodeSplitHistory bool           `json:"area_code_split_history"`
	LikelyPorted         bool           `json:"likely_ported"`
	PortedReason         string         `json:"ported_reason"`
	TimezoneDetail       TimezoneDetail `json:"timezone_detail"`
	RegionalRiskFlag     bool           `json:"regional_risk_flag"`
	RegionalRiskRegion   string         `json:"regional_risk_region,omitempty"`
	RegionalRiskBasis    string         `json:"regional_risk_basis,omitempty"`
}

type TimezoneDetail struct {
	Name          string `json:"name"`
	UTCOffset     string `json:"utc_offset"`
	LocalTime     string `json:"local_time"`
	BusinessHours bool   `json:"business_hours"`
}

type areaCodeRecord struct {
	AreaCode          string   `json:"area_code"`
	Country           string   `json:"country"`
	Origin            string   `json:"origin"`
	RegionName        string   `json:"region_name"`
	Timezone          string   `json:"timezone"`
	SplitOrOverlay    bool     `json:"split_or_overlay"`
	History           []string `json:"history"`
	HistoricalCarrier string   `json:"historical_carrier"`
}

type riskDataset struct {
	AreaCodes    []riskRecord `json:"area_codes"`
	CountryCodes []riskRecord `json:"country_codes"`
}

type riskRecord struct {
	AreaCode    string `json:"area_code"`
	CountryCode string `json:"country_code"`
	Region      string `json:"region"`
	Basis       string `json:"basis"`
}

func New(opts ...Option) *Module {
	m := &Module{
		now:       time.Now,
		areaCodes: loadAreaCodes(),
		risk:      loadRiskDataset(),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func WithNow(now func() time.Time) Option {
	return func(m *Module) {
		if now != nil {
			m.now = now
		}
	}
}

func (m *Module) Name() string {
	return moduleName
}

func (m *Module) Description() string {
	return "Area-code history, timezone, portability, and regional complaint-pattern intelligence."
}

func (m *Module) RequiresAPIKey() bool {
	return false
}

func (m *Module) Tier() core.ModuleTier {
	return core.TierPassive
}

func (m *Module) DryRun(ctx context.Context, number *core.PhoneNumber) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (m *Module) Run(ctx context.Context, number *core.PhoneNumber) (*core.ModuleResult, error) {
	return m.run(ctx, number)
}

func (m *Module) RunPassive(ctx context.Context, number *core.PhoneNumber) (*core.ModuleResult, error) {
	return m.run(ctx, number)
}

func (m *Module) run(_ context.Context, number *core.PhoneNumber) (*core.ModuleResult, error) {
	record, areaCode := m.lookupAreaCode(number)
	result := Result{
		AreaCodeOrigin: "unknown",
		PortedReason:   "not enough historical carrier data to infer portability",
	}

	if record.AreaCode != "" {
		result.AreaCodeOrigin = record.Origin
		result.AreaCodeSplitHistory = record.SplitOrOverlay
		result.LikelyPorted, result.PortedReason = likelyPorted(number, record)
	}

	result.TimezoneDetail = m.timezoneDetail(number, record)
	if risk, ok := m.lookupRisk(number, areaCode); ok {
		result.RegionalRiskFlag = true
		result.RegionalRiskRegion = risk.Region
		result.RegionalRiskBasis = risk.Basis
	}

	return &core.ModuleResult{
		ModuleName: m.Name(),
		Status:     core.ModuleStatusSuccess,
		Findings:   result.findings(),
		Data:       result,
		Evidence:   []string{"Embedded NANP area-code history and public complaint-pattern region data."},
	}, nil
}

func (r Result) findings() map[string]string {
	return map[string]string{
		"area_code_origin":         emptyToUnknown(r.AreaCodeOrigin),
		"area_code_split_history":  strconv.FormatBool(r.AreaCodeSplitHistory),
		"likely_ported":            strconv.FormatBool(r.LikelyPorted),
		"ported_reason":            emptyToUnknown(r.PortedReason),
		"timezone_name":            emptyToUnknown(r.TimezoneDetail.Name),
		"utc_offset":               emptyToUnknown(r.TimezoneDetail.UTCOffset),
		"local_time":               emptyToUnknown(r.TimezoneDetail.LocalTime),
		"business_hours":           strconv.FormatBool(r.TimezoneDetail.BusinessHours),
		"regional_risk_flag":       strconv.FormatBool(r.RegionalRiskFlag),
		"regional_risk_region":     emptyToUnknown(r.RegionalRiskRegion),
		"regional_risk_basis":      emptyToUnknown(r.RegionalRiskBasis),
		"regional_risk_disclaimer": "informational public complaint-pattern context only; not a definitive classification of the number",
	}
}

func (m *Module) lookupAreaCode(number *core.PhoneNumber) (areaCodeRecord, string) {
	if number == nil || number.CountryCode != 1 {
		return areaCodeRecord{}, ""
	}
	digits := onlyDigits(number.NationalNumber)
	if len(digits) < 3 {
		return areaCodeRecord{}, ""
	}
	areaCode := digits[:3]
	return m.areaCodes[areaCode], areaCode
}

func (m *Module) timezoneDetail(number *core.PhoneNumber, record areaCodeRecord) TimezoneDetail {
	tzName := firstNonEmpty(record.Timezone, firstTimezone(number))
	detail := TimezoneDetail{Name: tzName}
	if tzName == "" || strings.EqualFold(tzName, "unknown") {
		return detail
	}

	location, err := time.LoadLocation(tzName)
	if err != nil {
		return detail
	}
	local := m.now().In(location)
	_, offsetSeconds := local.Zone()
	detail.UTCOffset = formatOffset(offsetSeconds)
	detail.LocalTime = local.Format("2006-01-02 15:04 MST")
	detail.BusinessHours = local.Hour() >= 9 && local.Hour() < 17
	return detail
}

func (m *Module) lookupRisk(number *core.PhoneNumber, areaCode string) (riskRecord, bool) {
	if areaCode != "" {
		for _, risk := range m.risk.AreaCodes {
			if risk.AreaCode == areaCode {
				return risk, true
			}
		}
	}
	if number == nil {
		return riskRecord{}, false
	}
	countryCode := strconv.Itoa(number.CountryCode)
	for _, risk := range m.risk.CountryCodes {
		if risk.CountryCode == countryCode {
			return risk, true
		}
	}
	return riskRecord{}, false
}

func likelyPorted(number *core.PhoneNumber, record areaCodeRecord) (bool, string) {
	current := ""
	if number != nil {
		current = strings.TrimSpace(number.CarrierHint)
	}
	historical := strings.TrimSpace(record.HistoricalCarrier)
	if current == "" || historical == "" {
		return false, "not enough carrier data to compare current carrier with area-code history"
	}
	if carrierMatches(current, historical) {
		return false, fmt.Sprintf("current carrier hint %q is consistent with historical area-code carrier %q", current, historical)
	}
	return true, fmt.Sprintf("current carrier hint %q differs from historical area-code carrier %q", current, historical)
}

func carrierMatches(current, historical string) bool {
	current = normalizeCarrier(current)
	historical = normalizeCarrier(historical)
	return current == historical || strings.Contains(current, historical) || strings.Contains(historical, current)
}

func normalizeCarrier(value string) string {
	value = strings.ToLower(value)
	var b strings.Builder
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func loadAreaCodes() map[string]areaCodeRecord {
	data, err := dataFS.ReadFile("data/areacodes.json")
	if err != nil {
		return map[string]areaCodeRecord{}
	}
	var records []areaCodeRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return map[string]areaCodeRecord{}
	}
	out := make(map[string]areaCodeRecord, len(records))
	for _, record := range records {
		out[record.AreaCode] = record
	}
	return out
}

func loadRiskDataset() riskDataset {
	data, err := dataFS.ReadFile("data/high_risk_regions.json")
	if err != nil {
		return riskDataset{}
	}
	var dataset riskDataset
	if err := json.Unmarshal(data, &dataset); err != nil {
		return riskDataset{}
	}
	return dataset
}

func firstTimezone(number *core.PhoneNumber) string {
	if number == nil {
		return ""
	}
	for _, part := range strings.Split(number.Timezone, ",") {
		part = strings.TrimSpace(part)
		if part != "" && !strings.EqualFold(part, "unknown") {
			return part
		}
	}
	return ""
}

func formatOffset(seconds int) string {
	sign := "+"
	if seconds < 0 {
		sign = "-"
		seconds = -seconds
	}
	hours := seconds / 3600
	minutes := (seconds % 3600) / 60
	return fmt.Sprintf("%s%02d:%02d", sign, hours, minutes)
}

func onlyDigits(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func emptyToUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func (m *Module) ProxyAware() bool { return true }
