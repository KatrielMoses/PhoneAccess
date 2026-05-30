package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/config"
	"github.com/KatrielMoses/PhoneAccess/internal/core"
	"github.com/KatrielMoses/PhoneAccess/internal/correlator"
)

type SourceTier string

const (
	TierGovernment  SourceTier = "Government"
	TierCommercial  SourceTier = "Commercial"
	TierCrowdsource SourceTier = "Crowdsource"
	TierBreach      SourceTier = "Breach"
	TierInference   SourceTier = "Inference"
)

type RateLimitConfig struct {
	Requests int           `json:"requests"`
	Window   time.Duration `json:"window"`
}

type PhoneSource interface {
	Name() string
	Tier() SourceTier
	Jurisdiction() []string
	DryRun(ctx context.Context, e164 string) error
	Fetch(ctx context.Context, e164 string) ([]correlator.PIIClaim, error)
	RateLimit() RateLimitConfig
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type ResponseCache interface {
	GetOrFetch(ctx context.Context, key string, fetch func(context.Context) ([]byte, error)) ([]byte, error)
}

type cacheContextKey struct{}

const MaxBodyBytes = 2 * 1024 * 1024

var ErrSkipped = errors.New("source skipped")

func ContextWithResponseCache(ctx context.Context, cache ResponseCache) context.Context {
	if cache == nil {
		return ctx
	}
	return context.WithValue(ctx, cacheContextKey{}, cache)
}

func ResponseCacheFromContext(ctx context.Context) ResponseCache {
	cache, _ := ctx.Value(cacheContextKey{}).(ResponseCache)
	return cache
}

func TierWeight(tier SourceTier) float64 {
	switch tier {
	case TierGovernment:
		return 0.90
	case TierCommercial:
		return 0.75
	case TierCrowdsource:
		return 0.50
	case TierBreach:
		return 0.25
	case TierInference:
		return 0.10
	default:
		return 0.10
	}
}

func SourceMeta(name string, tier SourceTier, jurisdiction []string) correlator.SourceMeta {
	return correlator.SourceMeta{
		Name:          name,
		Tier:          string(tier),
		TierWeight:    TierWeight(tier),
		Jurisdictions: append([]string(nil), jurisdiction...),
	}
}

func NewClaim(field, value string, meta correlator.SourceMeta, fetchedAt time.Time) correlator.PIIClaim {
	return correlator.PIIClaim{
		Field:     field,
		Value:     value,
		Source:    meta,
		Weight:    meta.TierWeight,
		FetchedAt: fetchedAt,
	}
}

func LoadKey(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	store, err := config.NewDefaultStore()
	if err != nil {
		return ""
	}
	cfg, err := store.Load()
	if err != nil {
		return ""
	}
	for _, name := range names {
		if value := strings.TrimSpace(cfg.APIKeys[name]); value != "" {
			return value
		}
	}
	return ""
}

func GetJSON(ctx context.Context, client HTTPClient, endpoint string, headers map[string]string, target any) error {
	body, err := Get(ctx, client, endpoint, headers)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("decode json: %w", err)
	}
	return nil
}

func Get(ctx context.Context, client HTTPClient, endpoint string, headers map[string]string) ([]byte, error) {
	if client == nil {
		client = http.DefaultClient
	}
	fetch := func(ctx context.Context) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		SetDefaultHeaders(req)
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return nil, ErrSkipped
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("http status %d", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	}
	if cache := ResponseCacheFromContext(ctx); cache != nil {
		return cache.GetOrFetch(ctx, endpoint, fetch)
	}
	return fetch(ctx)
}

func SetDefaultHeaders(req *http.Request) {
	req.Header.Set("User-Agent", core.GetGlobalPool().GetUA())
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
}

func BuildURL(base string, pathParts []string, query map[string]string) string {
	endpoint, _ := url.Parse(strings.TrimRight(base, "/"))
	for _, part := range pathParts {
		endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/" + url.PathEscape(part)
	}
	values := endpoint.Query()
	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		values.Set(key, query[key])
	}
	endpoint.RawQuery = values.Encode()
	return endpoint.String()
}

func E164Digits(e164 string) string {
	return strings.TrimPrefix(strings.TrimSpace(e164), "+")
}
