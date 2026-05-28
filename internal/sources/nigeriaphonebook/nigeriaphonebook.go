package nigeriaphonebook

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
	"github.com/KatrielMoses/PhoneAccess/internal/correlator"
	"github.com/KatrielMoses/PhoneAccess/internal/sources"
)

const defaultBaseURL = "https://nigeriaphonebook.com/search/"

type Source struct {
	client  sources.HTTPClient
	baseURL string
	now     func() time.Time
	limiter *core.RateLimiter
}
type Option func(*Source)

func New(opts ...Option) *Source {
	s := &Source{client: http.DefaultClient, baseURL: defaultBaseURL, now: func() time.Time { return time.Now().UTC() }, limiter: core.NewRateLimiter(2 * time.Second)}
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
func WithNow(now func() time.Time) Option {
	return func(s *Source) {
		if now != nil {
			s.now = now
		}
	}
}
func WithRateLimiter(limiter *core.RateLimiter) Option {
	return func(s *Source) { s.limiter = limiter }
}

func (s *Source) Name() string             { return "NigeriaPhoneBook" }
func (s *Source) Tier() sources.SourceTier { return sources.TierCrowdsource }
func (s *Source) Jurisdiction() []string   { return []string{"NG"} }
func (s *Source) RateLimit() sources.RateLimitConfig {
	return sources.RateLimitConfig{Requests: 30, Window: time.Minute}
}
func (s *Source) DryRun(ctx context.Context, e164 string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if !strings.HasPrefix(e164, "+234") {
		return fmt.Errorf("skipped: NigeriaPhoneBook supports +234 numbers only")
	}
	return nil
}
func (s *Source) Fetch(ctx context.Context, e164 string) ([]correlator.PIIClaim, error) {
	if s.limiter != nil {
		if err := s.limiter.Wait(ctx, "nigeriaphonebook.com"); err != nil {
			return nil, err
		}
	}
	endpoint := sources.BuildURL(s.baseURL, nil, map[string]string{"q": national(e164, "+234")})
	body, err := sources.Get(ctx, s.client, endpoint, map[string]string{"Accept": "text/html,application/xhtml+xml"})
	if err != nil {
		return nil, nil
	}
	name := extractName(body)
	if name == "" {
		return nil, nil
	}
	meta := sources.SourceMeta(s.Name(), s.Tier(), s.Jurisdiction())
	return []correlator.PIIClaim{sources.NewClaim(correlator.FieldName, name, meta, s.now())}, nil
}

var tagRE = regexp.MustCompile(`(?s)<[^>]+>`)
var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func extractName(body []byte) string {
	text := html.UnescapeString(string(body))
	if m := titleRE.FindStringSubmatch(text); len(m) > 1 {
		text = m[1] + " " + text
	}
	text = strings.Join(strings.Fields(tagRE.ReplaceAllString(text, " ")), " ")
	for _, sep := range []string{" - ", "|", " Nigeria"} {
		text = strings.Split(text, sep)[0]
	}
	text = strings.Trim(text, ` "'`)
	if len(text) > 100 || strings.EqualFold(text, "search") {
		return ""
	}
	return text
}
func national(e164, prefix string) string {
	return strings.TrimPrefix(strings.TrimPrefix(e164, prefix), "+")
}
