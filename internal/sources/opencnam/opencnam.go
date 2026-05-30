package opencnam

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/correlator"
	"github.com/KatrielMoses/PhoneAccess/internal/sources"
)

const (
	defaultBaseURL = "https://api.opencnam.com/v2/phone"
	keyName        = "OPENCNAM_SID"
)

type Source struct {
	client  sources.HTTPClient
	baseURL string
	sid     string
	now     func() time.Time
}

type Option func(*Source)

func New(opts ...Option) *Source {
	s := &Source{
		client:  http.DefaultClient,
		baseURL: defaultBaseURL,
		sid:     sources.LoadKey(keyName, "opencnam_sid", "opencnam"),
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

func WithSID(sid string) Option { return func(s *Source) { s.sid = sid } }
func WithNow(now func() time.Time) Option {
	return func(s *Source) {
		if now != nil {
			s.now = now
		}
	}
}

func (s *Source) Name() string             { return "OpenCNAM" }
func (s *Source) Tier() sources.SourceTier { return sources.TierCommercial }
func (s *Source) Jurisdiction() []string   { return []string{"US", "CA", "ZZ"} }
func (s *Source) RateLimit() sources.RateLimitConfig {
	return sources.RateLimitConfig{Requests: 10, Window: time.Hour}
}

func (s *Source) DryRun(ctx context.Context, e164 string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (s *Source) Fetch(ctx context.Context, e164 string) ([]correlator.PIIClaim, error) {
	endpoint := sources.BuildURL(s.baseURL, []string{e164}, map[string]string{
		"format":      "json",
		"account_sid": s.sid,
	})
	body, err := sources.Get(ctx, s.client, endpoint, map[string]string{"Accept": "application/json"})
	if err != nil {
		return nil, nil
	}
	name := parseName(body)
	if name == "" || strings.EqualFold(name, "unknown") {
		return nil, nil
	}
	meta := sources.SourceMeta(s.Name(), s.Tier(), s.Jurisdiction())
	return []correlator.PIIClaim{sources.NewClaim(correlator.FieldName, name, meta, s.now())}, nil
}

func parseName(body []byte) string {
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return ""
	}
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v)
	case map[string]any:
		for _, key := range []string{"name", "cnam", "caller_name"} {
			if text, ok := v[key].(string); ok && strings.TrimSpace(text) != "" {
				return strings.TrimSpace(text)
			}
		}
	}
	return ""
}

func (s *Source) ProxyAware() bool { return true }
