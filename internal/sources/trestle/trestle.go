package trestle

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
	defaultBaseURL = "https://api.trestleiq.com/3.1/phone"
	keyName        = "TRESTLE_API_KEY"
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
		key:     sources.LoadKey(keyName, "trestle"),
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

func (s *Source) Name() string             { return "Trestle" }
func (s *Source) Tier() sources.SourceTier { return sources.TierCommercial }
func (s *Source) Jurisdiction() []string   { return []string{"US"} }
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
		return nil, nil
	}
	endpoint := sources.BuildURL(s.baseURL, nil, map[string]string{"phone": e164})
	var response trestleResponse
	headers := map[string]string{"Accept": "application/json", "x-api-key": s.key}
	if err := sources.GetJSON(ctx, s.client, endpoint, headers, &response); err != nil {
		return nil, nil
	}
	meta := sources.SourceMeta(s.Name(), s.Tier(), s.Jurisdiction())
	now := s.now()
	claims := []correlator.PIIClaim{}
	for _, person := range response.Entries() {
		if person.Name != "" {
			claims = append(claims, sources.NewClaim(correlator.FieldName, person.Name, meta, now))
		}
		if person.Address != "" {
			claim := sources.NewClaim(correlator.FieldAddress, person.Address, meta, now)
			if person.LastSeen != "" {
				if parsed, err := time.Parse("2006-01-02", person.LastSeen); err == nil {
					claim.VerifiedAt = &parsed
				}
			}
			claims = append(claims, claim)
		}
	}
	return claims, nil
}

type trestleResponse struct {
	Name     string          `json:"name"`
	Address  string          `json:"address"`
	AgeRange string          `json:"age_range"`
	Person   *trestlePerson  `json:"person"`
	People   []trestlePerson `json:"people"`
	Results  []trestlePerson `json:"results"`
}

type trestlePerson struct {
	Name     string `json:"name"`
	Address  string `json:"address"`
	AgeRange string `json:"age_range"`
	LastSeen string `json:"last_seen"`
}

func (r trestleResponse) Entries() []trestlePerson {
	out := []trestlePerson{}
	if r.Name != "" || r.Address != "" {
		out = append(out, trestlePerson{Name: r.Name, Address: r.Address, AgeRange: r.AgeRange})
	}
	if r.Person != nil {
		out = append(out, *r.Person)
	}
	out = append(out, r.People...)
	out = append(out, r.Results...)
	return out
}
