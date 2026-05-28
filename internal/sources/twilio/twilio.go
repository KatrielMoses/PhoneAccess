package twilio

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
	"github.com/KatrielMoses/PhoneAccess/internal/correlator"
	"github.com/KatrielMoses/PhoneAccess/internal/sources"
)

const (
	defaultBaseURL        = "https://lookups.twilio.com/v2/PhoneNumbers"
	accountSIDKeyName     = "TWILIO_ACCOUNT_SID"
	authTokenKeyName      = "TWILIO_AUTH_TOKEN"
	callerNameFlagKeyName = "TWILIO_ENABLE_CALLER_NAME"
)

type Source struct {
	client           sources.HTTPClient
	baseURL          string
	accountSID       string
	authToken        string
	enableCallerName bool
	now              func() time.Time
}

type Option func(*Source)

func New(opts ...Option) *Source {
	s := &Source{
		client:           http.DefaultClient,
		baseURL:          defaultBaseURL,
		accountSID:       sources.LoadKey(accountSIDKeyName, "twilio_account_sid"),
		authToken:        sources.LoadKey(authTokenKeyName, "twilio_auth_token"),
		enableCallerName: loadBool(sources.LoadKey(callerNameFlagKeyName, "twilio_enable_caller_name")),
		now:              func() time.Time { return time.Now().UTC() },
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func WithHTTPClient(client sources.HTTPClient) Option {
	return func(s *Source) {
		if client != nil {
			s.client = client
		}
	}
}

func WithBaseURL(baseURL string) Option {
	return func(s *Source) {
		if strings.TrimSpace(baseURL) != "" {
			s.baseURL = strings.TrimRight(baseURL, "/")
		}
	}
}

func WithCredentials(accountSID, authToken string) Option {
	return func(s *Source) {
		s.accountSID = strings.TrimSpace(accountSID)
		s.authToken = strings.TrimSpace(authToken)
	}
}

func WithCallerNameEnabled(enabled bool) Option {
	return func(s *Source) {
		s.enableCallerName = enabled
	}
}

func WithNow(now func() time.Time) Option {
	return func(s *Source) {
		if now != nil {
			s.now = now
		}
	}
}

func (s *Source) Name() string             { return "Twilio" }
func (s *Source) Tier() sources.SourceTier { return sources.TierCommercial }
func (s *Source) Jurisdiction() []string   { return []string{"ZZ"} }
func (s *Source) RateLimit() sources.RateLimitConfig {
	return sources.RateLimitConfig{Requests: 1000, Window: 24 * time.Hour}
}

func (s *Source) DryRun(ctx context.Context, e164 string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if strings.TrimSpace(s.accountSID) == "" || strings.TrimSpace(s.authToken) == "" {
		return fmt.Errorf("missing %s and %s", accountSIDKeyName, authTokenKeyName)
	}
	return nil
}

func (s *Source) Fetch(ctx context.Context, e164 string) ([]correlator.PIIClaim, error) {
	if strings.TrimSpace(s.accountSID) == "" || strings.TrimSpace(s.authToken) == "" {
		return nil, fmt.Errorf("missing %s and %s", accountSIDKeyName, authTokenKeyName)
	}

	endpoint, err := url.Parse(strings.TrimRight(s.baseURL, "/") + "/" + url.PathEscape(e164))
	if err != nil {
		return nil, err
	}
	query := endpoint.Query()
	query.Set("Fields", s.fieldsForNumber(e164))
	endpoint.RawQuery = query.Encode()

	var response twilioResponse
	if err := s.getJSON(ctx, endpoint.String(), &response); err != nil {
		return nil, err
	}

	meta := sources.SourceMeta(s.Name(), s.Tier(), s.Jurisdiction())
	now := s.now()
	claims := []correlator.PIIClaim{}
	if carrier := strings.TrimSpace(response.LineTypeIntelligence.CarrierName); carrier != "" {
		claim := sources.NewClaim(correlator.FieldCarrier, carrier, meta, now)
		claim.Metadata = map[string]string{
			"mobile_country_code": response.LineTypeIntelligence.MobileCountryCode,
			"mobile_network_code": response.LineTypeIntelligence.MobileNetworkCode,
		}
		claims = append(claims, claim)
	}
	if lineType := normalizeLineType(response.LineTypeIntelligence.Type); lineType != "" {
		claim := sources.NewClaim(correlator.FieldLineType, lineType, meta, now)
		claim.Metadata = map[string]string{
			"mobile_country_code": response.LineTypeIntelligence.MobileCountryCode,
			"mobile_network_code": response.LineTypeIntelligence.MobileNetworkCode,
		}
		claims = append(claims, claim)
	}
	if s.shouldRequestCallerName(e164) && response.CallerName.CallerName != "" {
		claim := sources.NewClaim(correlator.FieldName, response.CallerName.CallerName, meta, now)
		claim.Metadata = map[string]string{
			"caller_type":         response.CallerName.CallerType,
			"mobile_country_code": response.LineTypeIntelligence.MobileCountryCode,
			"mobile_network_code": response.LineTypeIntelligence.MobileNetworkCode,
			"source":              "Twilio",
		}
		claims = append(claims, claim)
	}
	return claims, nil
}

func (s *Source) fieldsForNumber(e164 string) string {
	fields := []string{"line_type_intelligence"}
	if s.shouldRequestCallerName(e164) {
		fields = append(fields, "caller_name")
	}
	return strings.Join(fields, ",")
}

func (s *Source) shouldRequestCallerName(e164 string) bool {
	if !s.enableCallerName {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(e164), "+1")
}

func (s *Source) getJSON(ctx context.Context, endpoint string, target any) error {
	cache := sources.ResponseCacheFromContext(ctx)
	fetch := func(ctx context.Context) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		core.SetDefaultHeaders(req)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "PhoneAccess/0.1.0 (+https://github.com/KatrielMoses/PhoneAccess)")
		req.SetBasicAuth(s.accountSID, s.authToken)
		req.Header.Set("X-Timestamp", fmt.Sprintf("%d", s.now().UnixMilli()))

		resp, err := s.client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("http status %d", resp.StatusCode)
		}
		return io.ReadAll(resp.Body)
	}
	var (
		data []byte
		err  error
	)
	if cache != nil {
		data, err = cache.GetOrFetch(ctx, endpoint, fetch)
	} else {
		data, err = fetch(ctx)
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

func normalizeLineType(value string) string {
	switch strings.ToLower(strings.TrimSpace(strings.ReplaceAll(value, "_", "-"))) {
	case "mobile":
		return "mobile"
	case "landline":
		return "landline"
	case "fixedvoip", "nonfixedvoip", "voip":
		return "voip"
	case "tollfree", "toll-free":
		return "toll-free"
	case "premiumrate", "premium-rate":
		return "premium-rate"
	default:
		return "unknown"
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func loadBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

type twilioResponse struct {
	LineTypeIntelligence struct {
		CarrierName       string `json:"carrier_name"`
		Type              string `json:"type"`
		MobileCountryCode string `json:"mobile_country_code"`
		MobileNetworkCode string `json:"mobile_network_code"`
	} `json:"line_type_intelligence"`
	CallerName struct {
		CallerName string `json:"caller_name"`
		CallerType string `json:"caller_type"`
	} `json:"caller_name"`
}
