package leaksight

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
	defaultBaseURL = "https://api.leaksight.com/v1/search"
	keyName        = "LEAKSIGHT_API_KEY"
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
		key:     sources.LoadKey(keyName, "leaksight"),
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

func (s *Source) Name() string             { return "LeakSight" }
func (s *Source) Tier() sources.SourceTier { return sources.TierBreach }
func (s *Source) Jurisdiction() []string   { return []string{"ZZ"} }
func (s *Source) RateLimit() sources.RateLimitConfig {
	return sources.RateLimitConfig{Requests: 60, Window: time.Hour}
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
	endpoint := sources.BuildURL(s.baseURL, nil, map[string]string{"query": e164})
	var response leaksightResponse
	headers := map[string]string{"Accept": "application/json", "Authorization": "Bearer " + s.key, "X-API-Key": s.key}
	if err := sources.GetJSON(ctx, s.client, endpoint, headers, &response); err != nil {
		return nil, err
	}
	meta := sources.SourceMeta(s.Name(), s.Tier(), s.Jurisdiction())
	now := s.now()
	claims := []correlator.PIIClaim{}
	for _, item := range response.Items() {
		for _, name := range item.Names {
			claims = append(claims, sources.NewClaim(correlator.FieldName, name, meta, now))
		}
		for _, email := range item.Emails {
			claims = append(claims, sources.NewClaim(correlator.FieldEmail, email, meta, now))
		}
	}
	return claims, nil
}

type leaksightResponse struct {
	Results []leakItem `json:"results"`
	Data    []leakItem `json:"data"`
	Names   []string   `json:"names"`
	Emails  []string   `json:"emails"`
}

type leakItem struct {
	Name   string   `json:"name"`
	Names  []string `json:"names"`
	Email  string   `json:"email"`
	Emails []string `json:"emails"`
}

func (r leaksightResponse) Items() []leakItem {
	items := append([]leakItem{}, r.Results...)
	items = append(items, r.Data...)
	if len(r.Names) > 0 || len(r.Emails) > 0 {
		items = append(items, leakItem{Names: r.Names, Emails: r.Emails})
	}
	for i := range items {
		if items[i].Name != "" {
			items[i].Names = append(items[i].Names, items[i].Name)
		}
		if items[i].Email != "" {
			items[i].Emails = append(items[i].Emails, items[i].Email)
		}
	}
	return items
}
