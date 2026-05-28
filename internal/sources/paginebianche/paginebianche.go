package paginebianche

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

const defaultBaseURL = "https://www.paginebianche.it/rin"

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
func (s *Source) Name() string             { return "Pagine Bianche" }
func (s *Source) Tier() sources.SourceTier { return sources.TierCrowdsource }
func (s *Source) Jurisdiction() []string   { return []string{"IT"} }
func (s *Source) RateLimit() sources.RateLimitConfig {
	return sources.RateLimitConfig{Requests: 30, Window: time.Minute}
}
func (s *Source) DryRun(ctx context.Context, e164 string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if !strings.HasPrefix(e164, "+39") {
		return fmt.Errorf("skipped: Pagine Bianche supports +39 landlines only")
	}
	return nil
}
func (s *Source) Fetch(ctx context.Context, e164 string) ([]correlator.PIIClaim, error) {
	if s.limiter != nil {
		if err := s.limiter.Wait(ctx, "paginebianche.it"); err != nil {
			return nil, err
		}
	}
	body, err := sources.Get(ctx, s.client, sources.BuildURL(s.baseURL, []string{national(e164, "+39")}, nil), map[string]string{"Accept": "text/html,application/xhtml+xml"})
	if err != nil {
		return nil, nil
	}
	name, address := parseHTML(body)
	meta, now := sources.SourceMeta(s.Name(), s.Tier(), s.Jurisdiction()), s.now()
	var claims []correlator.PIIClaim
	if name != "" {
		c := sources.NewClaim(correlator.FieldName, name, meta, now)
		c.Metadata = map[string]string{"landline_only": "true"}
		claims = append(claims, c)
	}
	if address != "" {
		c := sources.NewClaim(correlator.FieldAddress, address, meta, now)
		c.Metadata = map[string]string{"landline_only": "true"}
		claims = append(claims, c)
	}
	return claims, nil
}

var tagRE = regexp.MustCompile(`(?s)<[^>]+>`)
var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func parseHTML(body []byte) (string, string) {
	text := html.UnescapeString(string(body))
	title := ""
	if m := titleRE.FindStringSubmatch(text); len(m) > 1 {
		title = m[1]
	}
	clean := strings.Join(strings.Fields(tagRE.ReplaceAllString(text, " ")), " ")
	name := strings.Trim(strings.Split(strings.Split(title, "|")[0], "-")[0], ` "'`)
	if strings.Contains(strings.ToLower(name), "pagine") {
		name = ""
	}
	return trimLong(name), trimLong(extractAfter(clean, "Indirizzo"))
}
func extractAfter(text, marker string) string {
	i := strings.Index(strings.ToLower(text), strings.ToLower(marker))
	if i < 0 {
		return ""
	}
	tail := strings.TrimSpace(text[i+len(marker):])
	if len(tail) > 160 {
		tail = tail[:160]
	}
	return tail
}
func trimLong(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 120 {
		return ""
	}
	return value
}
func national(e164, prefix string) string {
	return strings.TrimPrefix(strings.TrimPrefix(e164, prefix), "+")
}
