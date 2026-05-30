package callerkit

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
	defaultBaseURL = "https://api.callerkit.com/v1/lookup"
	keyName        = "CALLERKIT_API_KEY"
)

var supportedPrefixes = []string{"+20", "+966", "+971", "+965", "+974", "+973", "+968", "+962", "+961", "+964", "+212", "+213", "+216", "+218", "+249"}

type Source struct {
	client  sources.HTTPClient
	baseURL string
	key     string
	now     func() time.Time
}

type Option func(*Source)

func New(opts ...Option) *Source {
	s := &Source{client: http.DefaultClient, baseURL: defaultBaseURL, key: sources.LoadKey(keyName, "callerkit"), now: func() time.Time { return time.Now().UTC() }}
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

func (s *Source) Name() string             { return "CallerKit" }
func (s *Source) Tier() sources.SourceTier { return sources.TierCommercial }
func (s *Source) Jurisdiction() []string {
	return []string{"EG", "SA", "AE", "KW", "QA", "BH", "OM", "JO", "LB", "IQ", "MA", "DZ", "TN", "LY", "SD"}
}
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
	if !supported(e164) {
		return fmt.Errorf("skipped: CallerKit supports MENA/North Africa numbers only")
	}
	return nil
}

func (s *Source) Fetch(ctx context.Context, e164 string) ([]correlator.PIIClaim, error) {
	endpoint := sources.BuildURL(s.baseURL, nil, map[string]string{"phone": e164, "key": s.key})
	var response struct {
		Name      string   `json:"name"`
		Aliases   []string `json:"aliases"`
		SpamCount int      `json:"spam_count"`
		Carrier   string   `json:"carrier"`
	}
	if err := sources.GetJSON(ctx, s.client, endpoint, map[string]string{"Accept": "application/json", "Authorization": "Bearer " + s.key}, &response); err != nil {
		return nil, err
	}
	meta, now := sources.SourceMeta(s.Name(), s.Tier(), s.Jurisdiction()), s.now()
	var claims []correlator.PIIClaim
	if response.Name != "" {
		claims = append(claims, sources.NewClaim(correlator.FieldName, response.Name, meta, now))
	}
	for _, alias := range response.Aliases {
		if strings.TrimSpace(alias) != "" {
			claims = append(claims, sources.NewClaim(correlator.FieldName, alias, meta, now))
		}
	}
	if response.Carrier != "" {
		claim := sources.NewClaim(correlator.FieldCarrier, response.Carrier, meta, now)
		claim.Metadata = map[string]string{"spam_count": fmt.Sprintf("%d", response.SpamCount)}
		claims = append(claims, claim)
	}
	return claims, nil
}

func supported(e164 string) bool {
	for _, prefix := range supportedPrefixes {
		if strings.HasPrefix(e164, prefix) {
			return true
		}
	}
	return false
}

func (s *Source) ProxyAware() bool { return true }
