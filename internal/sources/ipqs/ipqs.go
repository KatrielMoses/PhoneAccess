package ipqs

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
	defaultBaseURL = "https://www.ipqualityscore.com/api/json/phone"
	keyName        = "IPQS_API_KEY"
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
		key:     sources.LoadKey(keyName, "ipqualityscore", "ipqs"),
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
func WithAPIKey(key string) Option { return func(s *Source) { s.key = key } }
func WithNow(now func() time.Time) Option {
	return func(s *Source) {
		if now != nil {
			s.now = now
		}
	}
}

func (s *Source) Name() string             { return "IPQualityScore" }
func (s *Source) Tier() sources.SourceTier { return sources.TierCommercial }
func (s *Source) Jurisdiction() []string   { return []string{"US", "CA", "IN", "ZZ"} }
func (s *Source) RateLimit() sources.RateLimitConfig {
	return sources.RateLimitConfig{Requests: 60, Window: time.Minute}
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
	endpoint := sources.BuildURL(s.baseURL, []string{s.key, e164}, nil)
	var response struct {
		Name     string `json:"name"`
		Carrier  string `json:"carrier"`
		LineType string `json:"line_type"`
		Country  string `json:"country"`
		Region   string `json:"region"`
		City     string `json:"city"`
	}
	if err := sources.GetJSON(ctx, s.client, endpoint, map[string]string{"Accept": "application/json"}, &response); err != nil {
		return nil, err
	}
	meta := sources.SourceMeta(s.Name(), s.Tier(), s.Jurisdiction())
	now := s.now()
	claims := []correlator.PIIClaim{}
	if response.Name != "" {
		claims = append(claims, sources.NewClaim(correlator.FieldName, response.Name, meta, now))
	}
	if region := firstNonEmpty(response.City, response.Region, response.Country); region != "" {
		claim := sources.NewClaim(correlator.FieldRegion, region, meta, now)
		claim.Weight = meta.TierWeight * 0.50
		claims = append(claims, claim)
	}
	if response.Carrier != "" {
		claims = append(claims, sources.NewClaim(correlator.FieldCarrier, response.Carrier, meta, now))
	}
	if response.LineType != "" {
		claims = append(claims, sources.NewClaim(correlator.FieldLineType, response.LineType, meta, now))
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
