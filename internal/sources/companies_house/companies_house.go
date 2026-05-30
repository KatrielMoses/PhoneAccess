package companies_house

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/correlator"
	"github.com/KatrielMoses/PhoneAccess/internal/sources"
)

const defaultBaseURL = "https://api.company-information.service.gov.uk/search/officers"

type Source struct {
	client         sources.HTTPClient
	baseURL        string
	candidateNames []string
	now            func() time.Time
}

type Option func(*Source)

func New(opts ...Option) *Source {
	s := &Source{
		client:  http.DefaultClient,
		baseURL: defaultBaseURL,
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
func WithCandidateNames(names []string) Option {
	return func(s *Source) {
		s.candidateNames = append([]string(nil), names...)
	}
}
func WithNow(now func() time.Time) Option {
	return func(s *Source) {
		if now != nil {
			s.now = now
		}
	}
}

func (s *Source) Name() string             { return "Companies House" }
func (s *Source) Tier() sources.SourceTier { return sources.TierGovernment }
func (s *Source) Jurisdiction() []string   { return []string{"GB"} }
func (s *Source) RateLimit() sources.RateLimitConfig {
	return sources.RateLimitConfig{Requests: 600, Window: 5 * time.Minute}
}

func (s *Source) DryRun(ctx context.Context, e164 string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if !strings.HasPrefix(e164, "+44") {
		return fmt.Errorf("skipped: Companies House supports GB numbers only")
	}
	if len(s.candidateNames) == 0 {
		return fmt.Errorf("skipped: no candidate names available for Companies House")
	}
	return nil
}

func (s *Source) WithCandidateNames(names []string) correlator.ClaimSource {
	clone := *s
	clone.candidateNames = append([]string(nil), names...)
	return &clone
}

func (s *Source) Fetch(ctx context.Context, e164 string) ([]correlator.PIIClaim, error) {
	if !strings.HasPrefix(e164, "+44") || len(s.candidateNames) == 0 {
		return nil, nil
	}
	meta := sources.SourceMeta(s.Name(), s.Tier(), s.Jurisdiction())
	var claims []correlator.PIIClaim
	for _, name := range s.candidateNames {
		endpoint := sources.BuildURL(s.baseURL, nil, map[string]string{"q": name})
		var response officersResponse
		if err := sources.GetJSON(ctx, s.client, endpoint, map[string]string{"Accept": "application/json"}, &response); err != nil {
			continue
		}
		for _, item := range response.Items {
			if strings.TrimSpace(item.Title) != "" {
				claims = append(claims, sources.NewClaim(correlator.FieldName, item.Title, meta, s.now()))
			}
			if address := item.Address.String(); address != "" {
				claim := sources.NewClaim(correlator.FieldAddress, address, meta, s.now())
				claims = append(claims, claim)
			}
			if item.DateOfBirth.Year > 0 {
				dob := fmt.Sprintf("%04d", item.DateOfBirth.Year)
				precision := "year"
				if item.DateOfBirth.Month > 0 {
					dob = fmt.Sprintf("%04d-%02d", item.DateOfBirth.Year, item.DateOfBirth.Month)
					precision = "month"
				}
				claim := sources.NewClaim(correlator.FieldDOB, dob, meta, s.now())
				claim.Precision = precision
				claims = append(claims, claim)
			}
		}
	}
	return claims, nil
}

type officersResponse struct {
	Items []officerItem `json:"items"`
}

type officerItem struct {
	Title       string  `json:"title"`
	Address     address `json:"address"`
	DateOfBirth struct {
		Month int `json:"month"`
		Year  int `json:"year"`
	} `json:"date_of_birth"`
}

type address struct {
	Premises     string `json:"premises"`
	AddressLine1 string `json:"address_line_1"`
	AddressLine2 string `json:"address_line_2"`
	Locality     string `json:"locality"`
	Region       string `json:"region"`
	PostalCode   string `json:"postal_code"`
	Country      string `json:"country"`
}

func (a address) String() string {
	parts := []string{a.Premises, a.AddressLine1, a.AddressLine2, a.Locality, a.Region, a.PostalCode, a.Country}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.TrimSpace(part) != "" {
			out = append(out, strings.TrimSpace(part))
		}
	}
	return strings.Join(out, ", ")
}

func (s *Source) ProxyAware() bool { return true }
