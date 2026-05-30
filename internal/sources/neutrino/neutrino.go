package neutrino

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/correlator"
	"github.com/KatrielMoses/PhoneAccess/internal/sources"
)

const (
	defaultEndpoint = "https://neutrinoapi.net/hlr-lookup"
	keyName         = "NEUTRINO_API_KEY"
	userIDName      = "NEUTRINO_USER_ID"
)

type Source struct {
	client   sources.HTTPClient
	endpoint string
	key      string
	userID   string
	now      func() time.Time
}

type Option func(*Source)

func New(opts ...Option) *Source {
	s := &Source{client: http.DefaultClient, endpoint: defaultEndpoint, key: sources.LoadKey(keyName, "neutrino_api_key"), userID: sources.LoadKey(userIDName, "neutrino_user_id"), now: func() time.Time { return time.Now().UTC() }}
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
func WithEndpoint(endpoint string) Option {
	return func(s *Source) {
		if strings.TrimSpace(endpoint) != "" {
			s.endpoint = endpoint
		}
	}
}
func WithCredentials(userID, key string) Option {
	return func(s *Source) { s.userID, s.key = userID, key }
}
func WithNow(now func() time.Time) Option {
	return func(s *Source) {
		if now != nil {
			s.now = now
		}
	}
}

func (s *Source) Name() string             { return "Neutrino HLR" }
func (s *Source) Tier() sources.SourceTier { return sources.TierCommercial }
func (s *Source) Jurisdiction() []string   { return []string{"ZZ"} }
func (s *Source) RateLimit() sources.RateLimitConfig {
	return sources.RateLimitConfig{Requests: 60, Window: time.Minute}
}
func (s *Source) DryRun(ctx context.Context, e164 string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if strings.TrimSpace(s.key) == "" || strings.TrimSpace(s.userID) == "" {
		return fmt.Errorf("missing %s or %s", keyName, userIDName)
	}
	return nil
}

func (s *Source) Fetch(ctx context.Context, e164 string) ([]correlator.PIIClaim, error) {
	form := url.Values{"number": {e164}, "user-id": {s.userID}, "api-key": {s.key}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	sources.SetDefaultHeaders(req)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, sources.MaxBodyBytes))
	if err != nil {
		return nil, err
	}
	var response struct {
		HLRValid        bool   `json:"hlr-valid"`
		HLRStatus       string `json:"hlr-status"`
		Ported          bool   `json:"ported"`
		Roaming         bool   `json:"roaming"`
		IMSI            string `json:"imsi"`
		CurrentNetwork  string `json:"current-network"`
		OriginalNetwork string `json:"original-network"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}
	meta, now := sources.SourceMeta(s.Name(), s.Tier(), s.Jurisdiction()), s.now()
	network := firstNonEmpty(response.CurrentNetwork, response.OriginalNetwork)
	if network == "" {
		return nil, nil
	}
	claim := sources.NewClaim(correlator.FieldCarrier, network, meta, now)
	claim.Metadata = map[string]string{
		"hlr_live":    fmt.Sprintf("%t", response.HLRValid || strings.EqualFold(response.HLRStatus, "ok")),
		"hlr_ported":  fmt.Sprintf("%t", response.Ported),
		"hlr_roaming": fmt.Sprintf("%t", response.Roaming),
		"imsi":        response.IMSI,
	}
	return []correlator.PIIClaim{claim}, nil
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
