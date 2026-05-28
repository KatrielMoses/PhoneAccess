package numlookup

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
	defaultBaseURL = "https://api.numlookupapi.com/v1/info"
	keyName        = "NUMLOOKUP_API_KEY"
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
		key:     sources.LoadKey(keyName, "numlookup"),
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

func (s *Source) Name() string             { return "NumLookup" }
func (s *Source) Tier() sources.SourceTier { return sources.TierCommercial }
func (s *Source) Jurisdiction() []string   { return []string{"US", "CA", "IN", "GB", "ZZ"} }
func (s *Source) RateLimit() sources.RateLimitConfig {
	return sources.RateLimitConfig{Requests: 500, Window: 30 * 24 * time.Hour}
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
	endpoint := sources.BuildURL(s.baseURL, []string{e164}, map[string]string{"apikey": s.key})
	var response struct {
		Name       string `json:"name"`
		CallerName string `json:"caller_name"`
		Carrier    string `json:"carrier"`
		LineType   string `json:"line_type"`
		Type       string `json:"type"`
		Region     string `json:"region"`
		Location   string `json:"location"`
		Country    string `json:"country"`
	}
	if err := sources.GetJSON(ctx, s.client, endpoint, nil, &response); err != nil {
		return nil, err
	}
	meta := sources.SourceMeta(s.Name(), s.Tier(), s.Jurisdiction())
	now := s.now()
	claims := []correlator.PIIClaim{}
	if name := firstNonEmpty(response.Name, response.CallerName); name != "" {
		claims = append(claims, sources.NewClaim(correlator.FieldName, name, meta, now))
	}
	if region := firstNonEmpty(response.Region, response.Location); region != "" {
		claim := sources.NewClaim(correlator.FieldRegion, region, meta, now)
		claim.Weight = meta.TierWeight * 0.60
		claims = append(claims, claim)
	}
	if response.Carrier != "" {
		claims = append(claims, sources.NewClaim(correlator.FieldCarrier, response.Carrier, meta, now))
	}
	if lineType := firstNonEmpty(response.LineType, response.Type); lineType != "" {
		claims = append(claims, sources.NewClaim(correlator.FieldLineType, lineType, meta, now))
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
