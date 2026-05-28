package carrier

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/config"
	"github.com/KatrielMoses/PhoneAccess/internal/core"
	"github.com/KatrielMoses/PhoneAccess/internal/correlator"
	"github.com/KatrielMoses/PhoneAccess/internal/sources/twilio"
	"github.com/nyaruka/phonenumbers"
)

const (
	moduleName              = "carrier"
	numVerifyURL            = "http://apilayer.net/api/validate"
	abstractAPIURL          = "https://phonevalidation.abstractapi.com/v1/"
	numVerifyKeyName        = "NUMVERIFY_API_KEY"
	abstractKeyName         = "ABSTRACT_API_KEY"
	twilioSIDKeyName        = "TWILIO_ACCOUNT_SID"
	twilioAuthKeyName       = "TWILIO_AUTH_TOKEN"
	twilioCallerNameKeyName = "TWILIO_ENABLE_CALLER_NAME"
)

var errNonOKStatus = errors.New("non-2xx response")

//go:embed data/voip_prefixes.json
var dataFS embed.FS

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Module struct {
	httpClient   HTTPClient
	keyLoader    func() apiKeys
	limiter      *core.RateLimiter
	numVerifyURL string
	abstractURL  string
	voipPrefixes []VOIPPrefix
}

type Option func(*Module)

type apiKeys struct {
	numVerify        string
	abstract         string
	twilioSID        string
	twilioAuth       string
	twilioCallerName bool
}

type VOIPPrefix struct {
	Provider string      `json:"provider"`
	Country  string      `json:"country"`
	Prefixes []string    `json:"prefixes"`
	Ranges   []VOIPRange `json:"ranges"`
}

type VOIPRange struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

func New(opts ...Option) *Module {
	m := &Module{
		httpClient:   core.NewHTTPClient(core.DefaultHTTPTimeout),
		keyLoader:    loadAPIKeys,
		limiter:      core.NewRateLimiter(time.Second),
		numVerifyURL: numVerifyURL,
		abstractURL:  abstractAPIURL,
		voipPrefixes: loadVOIPPrefixes(),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func WithHTTPClient(client HTTPClient) Option {
	return func(m *Module) {
		if client != nil {
			m.httpClient = client
		}
	}
}

func WithAPIKeys(numVerifyKey, abstractKey string) Option {
	return func(m *Module) {
		prev := m.keyLoader
		m.keyLoader = func() apiKeys {
			keys := prev()
			keys.numVerify = numVerifyKey
			keys.abstract = abstractKey
			return keys
		}
	}
}

func WithTwilioCredentials(accountSID, authToken string, enableCallerName bool) Option {
	return func(m *Module) {
		prev := m.keyLoader
		m.keyLoader = func() apiKeys {
			keys := prev()
			keys.twilioSID = strings.TrimSpace(accountSID)
			keys.twilioAuth = strings.TrimSpace(authToken)
			keys.twilioCallerName = enableCallerName
			return keys
		}
	}
}

func WithEndpoints(numVerifyEndpoint, abstractEndpoint string) Option {
	return func(m *Module) {
		if strings.TrimSpace(numVerifyEndpoint) != "" {
			m.numVerifyURL = numVerifyEndpoint
		}
		if strings.TrimSpace(abstractEndpoint) != "" {
			m.abstractURL = abstractEndpoint
		}
	}
}

func WithRateLimiter(limiter *core.RateLimiter) Option {
	return func(m *Module) {
		m.limiter = limiter
	}
}

func (m *Module) Name() string {
	return moduleName
}

func (m *Module) Description() string {
	return "Offline carrier, line type, VOIP, and regional phone intelligence with optional validation APIs."
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
	if number == nil {
		number = &core.PhoneNumber{LineType: core.LineTypeUnknown}
	}

	findings := m.offlineFindings(number)
	numVerifyFields := map[string]bool{}
	sources := []string{"offline"}

	keys := m.keyLoader()
	if strings.TrimSpace(keys.numVerify) != "" && m.applyNumVerify(ctx, keys.numVerify, number, findings, numVerifyFields) {
		sources = append(sources, "numverify")
	}
	if strings.TrimSpace(keys.abstract) != "" && m.applyAbstractAPI(ctx, keys.abstract, number, findings, numVerifyFields) {
		sources = append(sources, "abstractapi")
	}
	if strings.TrimSpace(keys.twilioSID) != "" && strings.TrimSpace(keys.twilioAuth) != "" && m.applyTwilio(ctx, keys, number, findings, numVerifyFields) {
		sources = append(sources, "twilio")
	}

	findings["data_source"] = summarizeSources(sources)
	findings["data_sources"] = strings.Join(sources, ", ")

	return &core.ModuleResult{
		ModuleName: m.Name(),
		Status:     core.ModuleStatusSuccess,
		Findings:   findings,
		Evidence:   []string{"Offline libphonenumber metadata and embedded VOIP prefix intelligence."},
	}, nil
}

func (m *Module) offlineFindings(number *core.PhoneNumber) map[string]string {
	findings := map[string]string{
		"carrier":                        emptyToUnknown(number.CarrierHint),
		"carrier_confidence":             confidence(number.CarrierHint != "", "medium", "low"),
		"line_type":                      string(number.LineType),
		"line_type_confidence":           confidence(number.LineType != core.LineTypeUnknown, "medium", "low"),
		"country":                        emptyToUnknown(number.CountryAlpha2),
		"country_confidence":             confidence(number.CountryAlpha2 != "", "medium", "low"),
		"region":                         emptyToUnknown(number.RegionDescription),
		"region_confidence":              confidence(number.RegionDescription != "", "medium", "low"),
		"valid":                          strconv.FormatBool(number.Valid),
		"valid_confidence":               confidence(number.Valid, "medium", "low"),
		"voip_suspected":                 "false",
		"voip_provider":                  "unknown",
		"voip_confidence":                "low",
		"timezone":                       emptyToUnknown(number.Timezone),
		"timezone_confidence":            confidence(number.Timezone != "", "medium", "low"),
		"local_format":                   emptyToUnknown(number.NationalNumber),
		"international_format":           emptyToUnknown(number.E164),
		"potentially_ported":             "unverifiable_offline",
		"potentially_ported_confidence":  "low",
		"ported_verification":            "offline metadata cannot verify number portability",
		"ported_verification_confidence": "low",
	}

	parsed := parseNumber(number)
	if parsed != nil {
		if carrierName, _ := phonenumbers.GetSafeCarrierDisplayNameForNumber(parsed, "en"); carrierName != "" {
			findings["carrier"] = carrierName
			findings["carrier_confidence"] = "medium"
		}
		if region, _ := phonenumbers.GetGeocodingForNumber(parsed, "en"); region != "" {
			findings["region"] = region
			findings["region_confidence"] = "medium"
		}
		if zones, _ := phonenumbers.GetTimezonesForNumber(parsed); len(zones) > 0 {
			findings["timezone"] = strings.Join(zones, ", ")
			findings["timezone_confidence"] = "medium"
		}
		findings["line_type"], findings["line_type_confidence"] = mapNumberType(phonenumbers.GetNumberType(parsed))
		findings["local_format"] = phonenumbers.Format(parsed, phonenumbers.NATIONAL)
		findings["international_format"] = phonenumbers.Format(parsed, phonenumbers.INTERNATIONAL)
	}

	if findings["line_type"] == string(core.LineTypeVoIP) {
		findings["voip_suspected"] = "true"
		findings["voip_confidence"] = "medium"
	}
	if provider := m.matchVOIPProvider(number); provider != "" {
		findings["voip_suspected"] = "true"
		findings["voip_provider"] = provider
		findings["voip_confidence"] = "medium"
		if findings["line_type"] == string(core.LineTypeUnknown) {
			findings["line_type"] = string(core.LineTypeVoIP)
			findings["line_type_confidence"] = "medium"
		}
	}

	return findings
}

func (m *Module) applyNumVerify(ctx context.Context, apiKey string, number *core.PhoneNumber, findings map[string]string, populated map[string]bool) bool {
	endpoint, err := url.Parse(m.numVerifyURL)
	if err != nil {
		return false
	}
	query := endpoint.Query()
	query.Set("access_key", apiKey)
	query.Set("number", lookupNumber(number))
	endpoint.RawQuery = query.Encode()

	var response numVerifyResponse
	if !m.getJSON(ctx, endpoint.String(), "numverify", &response) {
		return false
	}
	if response.Success != nil && !*response.Success {
		return false
	}

	applied := false
	if response.Valid != nil {
		applied = setAPIField(findings, populated, "valid", strconv.FormatBool(*response.Valid), "high") || applied
	}
	applied = setAPIField(findings, populated, "carrier", response.Carrier, "high") || applied
	if lineType := normalizeLineType(response.LineType); lineType != "" {
		applied = setAPIField(findings, populated, "line_type", lineType, "high") || applied
		if lineType == string(core.LineTypeVoIP) {
			applied = setAPIField(findings, populated, "voip_suspected", "true", "") || applied
			findings["voip_confidence"] = "high"
		}
	}
	if response.CountryName != "" {
		applied = setAPIField(findings, populated, "country", response.CountryName, "high") || applied
	} else {
		applied = setAPIField(findings, populated, "country", response.CountryCode, "high") || applied
	}
	applied = setAPIField(findings, populated, "region", response.Location, "high") || applied
	applied = setAPIField(findings, populated, "local_format", response.LocalFormat, "") || applied
	applied = setAPIField(findings, populated, "international_format", response.InternationalFormat, "") || applied

	return applied
}

func (m *Module) applyAbstractAPI(ctx context.Context, apiKey string, number *core.PhoneNumber, findings map[string]string, numVerifyFields map[string]bool) bool {
	endpoint, err := url.Parse(m.abstractURL)
	if err != nil {
		return false
	}
	query := endpoint.Query()
	query.Set("api_key", apiKey)
	query.Set("phone", lookupNumber(number))
	endpoint.RawQuery = query.Encode()

	var response abstractAPIResponse
	if !m.getJSON(ctx, endpoint.String(), "abstractapi", &response) {
		return false
	}

	applied := false
	if response.Valid != nil {
		applied = setAbstractField(findings, numVerifyFields, "valid", strconv.FormatBool(*response.Valid), "high") || applied
	}
	applied = setAbstractField(findings, numVerifyFields, "carrier", response.Carrier, "high") || applied
	if lineType := normalizeLineType(response.Type); lineType != "" {
		applied = setAbstractField(findings, numVerifyFields, "line_type", lineType, "high") || applied
		if lineType == string(core.LineTypeVoIP) {
			applied = setAbstractField(findings, numVerifyFields, "voip_suspected", "true", "") || applied
			findings["voip_confidence"] = "high"
		}
	}
	if response.Country.Name != "" {
		applied = setAbstractField(findings, numVerifyFields, "country", response.Country.Name, "high") || applied
	} else {
		applied = setAbstractField(findings, numVerifyFields, "country", response.Country.Code, "high") || applied
	}
	applied = setAbstractField(findings, numVerifyFields, "region", response.Location, "high") || applied
	applied = setAbstractField(findings, numVerifyFields, "local_format", firstNonEmpty(response.LocalFormat, response.Format.Local), "") || applied
	applied = setAbstractField(findings, numVerifyFields, "international_format", firstNonEmpty(response.InternationalFormat, response.Format.International, response.Phone), "") || applied

	return applied
}

func (m *Module) applyTwilio(ctx context.Context, keys apiKeys, number *core.PhoneNumber, findings map[string]string, populated map[string]bool) bool {
	source := twilio.New(
		twilio.WithHTTPClient(m.httpClient),
		twilio.WithCredentials(keys.twilioSID, keys.twilioAuth),
		twilio.WithCallerNameEnabled(keys.twilioCallerName),
		twilio.WithNow(time.Now),
	)
	claims, err := source.Fetch(ctx, lookupNumber(number))
	if err != nil {
		return false
	}

	applied := false
	for _, claim := range claims {
		switch claim.Field {
		case correlator.FieldCarrier:
			applied = setTwilioField(findings, populated, "carrier", claim.Value, "high") || applied
			if claim.Metadata != nil {
				applied = setTwilioField(findings, populated, "mobile_country_code", claim.Metadata["mobile_country_code"], "") || applied
				applied = setTwilioField(findings, populated, "mobile_network_code", claim.Metadata["mobile_network_code"], "") || applied
			}
		case correlator.FieldLineType:
			applied = setTwilioField(findings, populated, "line_type", normalizeLineType(claim.Value), "high") || applied
			if claim.Metadata != nil {
				applied = setTwilioField(findings, populated, "mobile_country_code", claim.Metadata["mobile_country_code"], "") || applied
				applied = setTwilioField(findings, populated, "mobile_network_code", claim.Metadata["mobile_network_code"], "") || applied
			}
			if normalizeLineType(claim.Value) == string(core.LineTypeVoIP) {
				applied = setTwilioField(findings, populated, "voip_suspected", "true", "") || applied
				findings["voip_confidence"] = "high"
			}
		case correlator.FieldName:
			applied = setTwilioField(findings, populated, "caller_name", claim.Value, "high") || applied
			if claim.Metadata != nil {
				applied = setTwilioField(findings, populated, "caller_type", claim.Metadata["caller_type"], "") || applied
			}
		}
	}
	return applied
}

func (m *Module) getJSON(ctx context.Context, endpoint, limitKey string, target any) bool {
	data, err := core.ResponseCacheFromContext(ctx).GetOrFetch(ctx, endpoint, func(ctx context.Context) ([]byte, error) {
		if m.limiter != nil {
			if err := m.limiter.Wait(ctx, limitKey); err != nil {
				return nil, err
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		core.SetDefaultHeaders(req)
		req.Header.Set("Accept", "application/json")
		resp, err := m.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, errNonOKStatus
		}
		return io.ReadAll(resp.Body)
	})
	if err != nil {
		return false
	}

	return json.Unmarshal(data, target) == nil
}

func (m *Module) matchVOIPProvider(number *core.PhoneNumber) string {
	e164 := lookupNumber(number)
	if e164 == "" {
		return ""
	}
	digits := strings.TrimPrefix(e164, "+")
	for _, entry := range m.voipPrefixes {
		if entry.Country != "" && number.CountryAlpha2 != "" && !strings.EqualFold(entry.Country, number.CountryAlpha2) {
			continue
		}
		for _, prefix := range entry.Prefixes {
			if strings.HasPrefix(e164, prefix) || strings.HasPrefix(digits, strings.TrimPrefix(prefix, "+")) {
				return entry.Provider
			}
		}
		for _, r := range entry.Ranges {
			if inRange(digits, strings.TrimPrefix(r.Start, "+"), strings.TrimPrefix(r.End, "+")) {
				return entry.Provider
			}
		}
	}
	return ""
}

func LoadVOIPPrefixes() []VOIPPrefix {
	return loadVOIPPrefixes()
}

func loadVOIPPrefixes() []VOIPPrefix {
	data, err := dataFS.ReadFile("data/voip_prefixes.json")
	if err != nil {
		return nil
	}
	var prefixes []VOIPPrefix
	if err := json.Unmarshal(data, &prefixes); err != nil {
		return nil
	}
	return prefixes
}

func loadAPIKeys() apiKeys {
	keys := apiKeys{
		numVerify:        os.Getenv(numVerifyKeyName),
		abstract:         os.Getenv(abstractKeyName),
		twilioSID:        os.Getenv(twilioSIDKeyName),
		twilioAuth:       os.Getenv(twilioAuthKeyName),
		twilioCallerName: configuredBool(os.Getenv(twilioCallerNameKeyName)),
	}

	store, err := config.NewDefaultStore()
	if err != nil {
		return keys
	}
	cfg, err := store.Load()
	if err != nil {
		return keys
	}
	if value := configuredKey(cfg.APIKeys, numVerifyKeyName, "numverify"); value != "" {
		keys.numVerify = value
	}
	if value := configuredKey(cfg.APIKeys, abstractKeyName, "abstractapi"); value != "" {
		keys.abstract = value
	}
	if value := configuredKey(cfg.APIKeys, twilioSIDKeyName, "twilio_account_sid"); value != "" {
		keys.twilioSID = value
	}
	if value := configuredKey(cfg.APIKeys, twilioAuthKeyName, "twilio_auth_token"); value != "" {
		keys.twilioAuth = value
	}
	if value := configuredKey(cfg.APIKeys, twilioCallerNameKeyName, "twilio_enable_caller_name"); value != "" {
		keys.twilioCallerName = configuredBool(value)
	}
	return keys
}

func configuredKey(keys map[string]string, names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(keys[name]); value != "" {
			return value
		}
	}
	return ""
}

func configuredBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func parseNumber(number *core.PhoneNumber) *phonenumbers.PhoneNumber {
	for _, candidate := range []string{number.E164, number.RawInput, number.NationalNumber} {
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		parsed, err := phonenumbers.Parse(candidate, firstNonEmpty(number.CountryAlpha2, "US"))
		if err == nil {
			return parsed
		}
	}
	return nil
}

func mapNumberType(kind phonenumbers.PhoneNumberType) (string, string) {
	switch kind {
	case phonenumbers.MOBILE:
		return string(core.LineTypeMobile), "high"
	case phonenumbers.FIXED_LINE:
		return string(core.LineTypeLandline), "high"
	case phonenumbers.FIXED_LINE_OR_MOBILE:
		return string(core.LineTypeMobile), "medium"
	case phonenumbers.VOIP:
		return string(core.LineTypeVoIP), "high"
	case phonenumbers.TOLL_FREE:
		return string(core.LineTypeTollFree), "high"
	case phonenumbers.PREMIUM_RATE:
		return string(core.LineTypePremiumRate), "high"
	default:
		return string(core.LineTypeUnknown), "low"
	}
}

func normalizeLineType(value string) string {
	switch strings.ToLower(strings.TrimSpace(strings.ReplaceAll(value, "_", "-"))) {
	case "mobile", "cell":
		return string(core.LineTypeMobile)
	case "landline", "fixed-line", "fixed":
		return string(core.LineTypeLandline)
	case "voip", "voip-phone":
		return string(core.LineTypeVoIP)
	case "toll-free", "tollfree":
		return string(core.LineTypeTollFree)
	case "premium-rate", "premium":
		return string(core.LineTypePremiumRate)
	default:
		return ""
	}
}

func setAPIField(findings map[string]string, populated map[string]bool, key, value, conf string) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	findings[key] = value
	populated[key] = true
	if conf != "" {
		findings[key+"_confidence"] = conf
	}
	return true
}

func setAbstractField(findings map[string]string, numVerifyFields map[string]bool, key, value, conf string) bool {
	if numVerifyFields[key] {
		return false
	}
	if strings.TrimSpace(value) == "" {
		return false
	}
	findings[key] = value
	if conf != "" {
		findings[key+"_confidence"] = conf
	}
	return true
}

func setTwilioField(findings map[string]string, populated map[string]bool, key, value, conf string) bool {
	if populated[key] {
		return false
	}
	return setAPIField(findings, populated, key, value, conf)
}

func lookupNumber(number *core.PhoneNumber) string {
	return firstNonEmpty(number.E164, number.RawInput, number.NationalNumber)
}

func inRange(number, start, end string) bool {
	return len(number) == len(start) && len(number) == len(end) && number >= start && number <= end
}

func summarizeSources(sources []string) string {
	for _, source := range sources {
		if source == "numverify" {
			return "numverify"
		}
	}
	for _, source := range sources {
		if source == "twilio" {
			return "twilio"
		}
	}
	for _, source := range sources {
		if source == "abstractapi" {
			return "abstractapi"
		}
	}
	return "offline"
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

func confidence(ok bool, good, fallback string) string {
	if ok {
		return good
	}
	return fallback
}

type numVerifyResponse struct {
	Success             *bool  `json:"success"`
	Valid               *bool  `json:"valid"`
	Number              string `json:"number"`
	LocalFormat         string `json:"local_format"`
	InternationalFormat string `json:"international_format"`
	CountryPrefix       string `json:"country_prefix"`
	CountryCode         string `json:"country_code"`
	CountryName         string `json:"country_name"`
	Location            string `json:"location"`
	Carrier             string `json:"carrier"`
	LineType            string `json:"line_type"`
}

type abstractAPIResponse struct {
	Valid               *bool  `json:"valid"`
	Phone               string `json:"phone"`
	LocalFormat         string `json:"local_format"`
	InternationalFormat string `json:"international_format"`
	Location            string `json:"location"`
	Type                string `json:"type"`
	Carrier             string `json:"carrier"`
	Format              struct {
		International string `json:"international"`
		Local         string `json:"local"`
	} `json:"format"`
	Country struct {
		Code   string `json:"code"`
		Name   string `json:"name"`
		Prefix string `json:"prefix"`
	} `json:"country"`
}
