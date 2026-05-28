package voip

import (
	"context"
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
	"github.com/KatrielMoses/PhoneAccess/internal/modules/carrier"
)

const (
	moduleName        = "voip"
	ipqsURL           = "https://www.ipqualityscore.com/api/json/phone"
	abstractAPIURL    = "https://phonevalidation.abstractapi.com/v1/"
	ipqsKeyName       = "IPQS_API_KEY"
	abstractKeyName   = "ABSTRACT_API_KEY"
	defaultNoProvider = "unknown"
)

var errNonOKStatus = errors.New("non-2xx response")

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Module struct {
	httpClient  HTTPClient
	keyLoader   func() apiKeys
	limiter     *core.RateLimiter
	ipqsURL     string
	abstractURL string
	prefixes    []carrier.VOIPPrefix
}

type Option func(*Module)

type apiKeys struct {
	ipqs     string
	abstract string
}

type Result struct {
	IsVOIP      bool     `json:"is_voip"`
	Confidence  string   `json:"confidence"`
	Provider    string   `json:"provider,omitempty"`
	IsPrepaid   bool     `json:"is_prepaid"`
	RiskSignals []string `json:"risk_signals"`
	DataSource  []string `json:"data_source"`
	Valid       *bool    `json:"valid,omitempty"`
	LineType    string   `json:"line_type,omitempty"`
	Active      *bool    `json:"active,omitempty"`
	Carrier     string   `json:"carrier,omitempty"`
	Country     string   `json:"country,omitempty"`
}

func New(opts ...Option) *Module {
	m := &Module{
		httpClient:  core.NewHTTPClient(core.DefaultHTTPTimeout),
		keyLoader:   loadAPIKeys,
		limiter:     core.NewRateLimiter(time.Second),
		ipqsURL:     ipqsURL,
		abstractURL: abstractAPIURL,
		prefixes:    carrier.LoadVOIPPrefixes(),
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

func WithAPIKeys(ipqsKey, abstractKey string) Option {
	return func(m *Module) {
		m.keyLoader = func() apiKeys {
			return apiKeys{ipqs: ipqsKey, abstract: abstractKey}
		}
	}
}

func WithEndpoints(ipqsEndpoint, abstractEndpoint string) Option {
	return func(m *Module) {
		if strings.TrimSpace(ipqsEndpoint) != "" {
			m.ipqsURL = ipqsEndpoint
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
	return "VOIP, disposable number, prepaid, and phone risk intelligence."
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
	return m.run(ctx, number, false)
}

func (m *Module) RunPassive(ctx context.Context, number *core.PhoneNumber) (*core.ModuleResult, error) {
	return m.run(ctx, number, true)
}

func (m *Module) run(ctx context.Context, number *core.PhoneNumber, passive bool) (*core.ModuleResult, error) {
	result := Result{
		Confidence:  "low",
		Provider:    defaultNoProvider,
		RiskSignals: []string{},
		DataSource:  []string{"offline"},
	}

	if number != nil && number.LineType == core.LineTypeVoIP {
		result.IsVOIP = true
		result.Confidence = "medium"
		result.LineType = string(core.LineTypeVoIP)
		result.DataSource = appendSource(result.DataSource, "libphonenumber")
		result.RiskSignals = appendSignal(result.RiskSignals, "libphonenumber classifies the line type as VOIP")
	}
	if provider := m.matchPrefix(number); provider != "" {
		result.IsVOIP = true
		result.Confidence = "high"
		result.Provider = provider
		result.DataSource = appendSource(result.DataSource, "embedded_prefixes")
		result.RiskSignals = appendSignal(result.RiskSignals, "number matches embedded VOIP provider prefix list")
	}

	if !passive {
		keys := m.keyLoader()
		if strings.TrimSpace(keys.ipqs) != "" {
			if response, ok := m.fetchIPQS(ctx, keys.ipqs, number); ok {
				m.applyIPQS(&result, response)
			}
		}
		if strings.TrimSpace(keys.abstract) != "" {
			if response, ok := m.fetchAbstract(ctx, keys.abstract, number); ok {
				m.applyAbstract(&result, response)
			}
		}
	}

	if result.Provider == "" {
		result.Provider = defaultNoProvider
	}

	findings := result.findings()
	if passive {
		findings["passive"] = "true"
	}

	return &core.ModuleResult{
		ModuleName: m.Name(),
		Status:     core.ModuleStatusSuccess,
		Findings:   findings,
		Data:       result,
		Evidence:   []string{"Embedded VOIP provider prefixes and optional phone validation API enrichment."},
	}, nil
}

func (r Result) findings() map[string]string {
	return map[string]string{
		"is_voip":      strconv.FormatBool(r.IsVOIP),
		"confidence":   r.Confidence,
		"provider":     emptyToUnknown(r.Provider),
		"is_prepaid":   strconv.FormatBool(r.IsPrepaid),
		"risk_signals": strings.Join(r.RiskSignals, "\n"),
		"data_source":  strings.Join(r.DataSource, ", "),
		"line_type":    r.LineType,
		"carrier":      r.Carrier,
		"country":      r.Country,
	}
}

func (m *Module) applyIPQS(result *Result, response ipqsResponse) {
	result.DataSource = appendSource(result.DataSource, "ipqualityscore")
	result.Valid = response.Valid
	result.Active = response.Active
	result.Country = firstNonEmpty(response.Country, result.Country)
	result.Carrier = firstNonEmpty(response.Carrier, result.Carrier)
	result.LineType = firstNonEmpty(normalizeLineType(response.LineType), result.LineType)

	if response.Prepaid != nil {
		result.IsPrepaid = *response.Prepaid
		if *response.Prepaid {
			result.RiskSignals = appendSignal(result.RiskSignals, "IPQualityScore reports the number as prepaid")
		}
	}
	if response.Risky != nil && *response.Risky {
		result.RiskSignals = appendSignal(result.RiskSignals, "IPQualityScore reports elevated phone risk")
	}
	if response.RecentAbuse != nil && *response.RecentAbuse {
		result.RiskSignals = appendSignal(result.RiskSignals, "IPQualityScore reports recent abuse activity")
	}
	if response.Active != nil && !*response.Active {
		result.RiskSignals = appendSignal(result.RiskSignals, "IPQualityScore reports the number as inactive")
	}
	if response.Valid != nil && !*response.Valid {
		result.RiskSignals = appendSignal(result.RiskSignals, "IPQualityScore reports the number as invalid")
	}

	if response.VOIP != nil {
		if *response.VOIP {
			result.IsVOIP = true
			result.Confidence = "high"
			result.RiskSignals = appendSignal(result.RiskSignals, "IPQualityScore reports VOIP=true")
		} else if !result.IsVOIP && result.Confidence == "low" {
			result.Confidence = "medium"
		}
	}
	if result.LineType == string(core.LineTypeVoIP) {
		result.IsVOIP = true
		result.Confidence = "high"
	}
	if result.Provider == defaultNoProvider && response.Carrier != "" && result.IsVOIP {
		result.Provider = response.Carrier
	}
}

func (m *Module) applyAbstract(result *Result, response abstractAPIResponse) {
	result.DataSource = appendSource(result.DataSource, "abstractapi")
	if response.Carrier != "" {
		result.Carrier = response.Carrier
		if result.Provider == defaultNoProvider && result.IsVOIP {
			result.Provider = response.Carrier
		}
	}
	if response.Country.Code != "" {
		result.Country = response.Country.Code
	}
	if lineType := normalizeLineType(response.Type); lineType != "" {
		result.LineType = lineType
		if lineType == string(core.LineTypeVoIP) {
			result.IsVOIP = true
			result.Confidence = "high"
			result.RiskSignals = appendSignal(result.RiskSignals, "AbstractAPI reports the line type as VOIP")
			if result.Provider == defaultNoProvider && response.Carrier != "" {
				result.Provider = response.Carrier
			}
		}
	}
	if response.Valid != nil {
		result.Valid = response.Valid
	}
}

func (m *Module) fetchIPQS(ctx context.Context, apiKey string, number *core.PhoneNumber) (ipqsResponse, bool) {
	endpoint := strings.TrimRight(m.ipqsURL, "/") + "/" + url.PathEscape(apiKey) + "/" + url.PathEscape(lookupNumber(number))
	var response ipqsResponse
	return response, m.getJSON(ctx, endpoint, "ipqualityscore", &response)
}

func (m *Module) fetchAbstract(ctx context.Context, apiKey string, number *core.PhoneNumber) (abstractAPIResponse, bool) {
	endpoint, err := url.Parse(m.abstractURL)
	if err != nil {
		return abstractAPIResponse{}, false
	}
	query := endpoint.Query()
	query.Set("api_key", apiKey)
	query.Set("phone", lookupNumber(number))
	endpoint.RawQuery = query.Encode()

	var response abstractAPIResponse
	return response, m.getJSON(ctx, endpoint.String(), "abstractapi", &response)
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

func (m *Module) matchPrefix(number *core.PhoneNumber) string {
	e164 := lookupNumber(number)
	if e164 == "" {
		return ""
	}
	digits := strings.TrimPrefix(e164, "+")
	for _, entry := range m.prefixes {
		if entry.Country != "" && number != nil && number.CountryAlpha2 != "" && !strings.EqualFold(entry.Country, number.CountryAlpha2) {
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

func loadAPIKeys() apiKeys {
	keys := apiKeys{
		ipqs:     os.Getenv(ipqsKeyName),
		abstract: os.Getenv(abstractKeyName),
	}
	store, err := config.NewDefaultStore()
	if err != nil {
		return keys
	}
	cfg, err := store.Load()
	if err != nil {
		return keys
	}
	if value := configuredKey(cfg.APIKeys, ipqsKeyName, "ipqualityscore", "ipqs"); value != "" {
		keys.ipqs = value
	}
	if value := configuredKey(cfg.APIKeys, abstractKeyName, "abstractapi"); value != "" {
		keys.abstract = value
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

func lookupNumber(number *core.PhoneNumber) string {
	if number == nil {
		return ""
	}
	return firstNonEmpty(number.E164, number.RawInput, number.NationalNumber)
}

func normalizeLineType(value string) string {
	switch strings.ToLower(strings.TrimSpace(strings.ReplaceAll(value, "_", "-"))) {
	case "mobile", "cell", "wireless":
		return string(core.LineTypeMobile)
	case "landline", "fixed-line", "fixed":
		return string(core.LineTypeLandline)
	case "voip", "voip-phone", "virtual":
		return string(core.LineTypeVoIP)
	case "toll-free", "tollfree":
		return string(core.LineTypeTollFree)
	case "premium-rate", "premium":
		return string(core.LineTypePremiumRate)
	default:
		return ""
	}
}

func inRange(number, start, end string) bool {
	return len(number) == len(start) && len(number) == len(end) && number >= start && number <= end
}

func appendSource(sources []string, source string) []string {
	for _, existing := range sources {
		if existing == source {
			return sources
		}
	}
	return append(sources, source)
}

func appendSignal(signals []string, signal string) []string {
	for _, existing := range signals {
		if existing == signal {
			return signals
		}
	}
	return append(signals, signal)
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

type ipqsResponse struct {
	Valid       *bool  `json:"valid"`
	LineType    string `json:"line_type"`
	Risky       *bool  `json:"risky"`
	RecentAbuse *bool  `json:"recent_abuse"`
	VOIP        *bool  `json:"voip"`
	Prepaid     *bool  `json:"prepaid"`
	Active      *bool  `json:"active"`
	Carrier     string `json:"carrier"`
	Country     string `json:"country"`
}

type abstractAPIResponse struct {
	Valid   *bool  `json:"valid"`
	Type    string `json:"type"`
	Carrier string `json:"carrier"`
	Country struct {
		Code string `json:"code"`
		Name string `json:"name"`
	} `json:"country"`
}
