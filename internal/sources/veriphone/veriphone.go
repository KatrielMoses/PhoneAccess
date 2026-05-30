package veriphone

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/correlator"
	"github.com/KatrielMoses/PhoneAccess/internal/sources"
)

const (
	defaultBaseURL = "https://api.veriphone.io/v2/verify"
	keyName        = "VERIPHONE_API_KEY"
)

type Source struct {
	client  sources.HTTPClient
	baseURL string
	key     string
	now     func() time.Time
}

type Option func(*Source)

func New(opts ...Option) *Source {
	s := &Source{
		client:  http.DefaultClient,
		baseURL: defaultBaseURL,
		key:     sources.LoadKey(keyName, "veriphone"),
		now:     func() time.Time { return time.Now().UTC() },
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
			s.baseURL = baseURL
		}
	}
}

func WithAPIKey(key string) Option {
	return func(s *Source) {
		s.key = key
	}
}

func WithNow(now func() time.Time) Option {
	return func(s *Source) {
		if now != nil {
			s.now = now
		}
	}
}

func (s *Source) Name() string             { return "Veriphone" }
func (s *Source) Tier() sources.SourceTier { return sources.TierCommercial }
func (s *Source) Jurisdiction() []string   { return []string{"ZZ"} }
func (s *Source) RateLimit() sources.RateLimitConfig {
	return sources.RateLimitConfig{Requests: 1000, Window: 30 * 24 * time.Hour}
}

func (s *Source) DryRun(ctx context.Context, e164 string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if strings.TrimSpace(s.key) == "" {
		return fmt.Errorf("missing %s", keyName)
	}
	return nil
}

func (s *Source) Fetch(ctx context.Context, e164 string) ([]correlator.PIIClaim, error) {
	if strings.TrimSpace(s.key) == "" {
		return nil, fmt.Errorf("missing %s", keyName)
	}
	endpoint := sources.BuildURL(s.baseURL, nil, map[string]string{
		"phone": e164,
		"key":   s.key,
	})

	var response struct {
		PhoneValid  bool   `json:"phone_valid"`
		PhoneType   string `json:"phone_type"`
		PhoneRegion string `json:"phone_region"`
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
		Carrier     string `json:"carrier"`
	}
	if err := sources.GetJSON(ctx, s.client, endpoint, map[string]string{"Accept": "application/json"}, &response); err != nil {
		return nil, err
	}

	meta := sources.SourceMeta(s.Name(), s.Tier(), s.Jurisdiction())
	now := s.now()
	claims := []correlator.PIIClaim{}
	if response.Carrier != "" {
		claims = append(claims, sources.NewClaim(correlator.FieldCarrier, response.Carrier, meta, now))
	}
	if response.PhoneType != "" {
		claims = append(claims, sources.NewClaim(correlator.FieldLineType, response.PhoneType, meta, now))
	}
	if region := firstNonEmpty(response.PhoneRegion, response.Country); region != "" {
		claim := sources.NewClaim(correlator.FieldRegion, region, meta, now)
		claim.Metadata = map[string]string{
			"valid":        fmt.Sprintf("%t", response.PhoneValid),
			"country_code": response.CountryCode,
		}
		claims = append(claims, claim)
	}
	return claims, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (s *Source) ProxyAware() bool { return true }
