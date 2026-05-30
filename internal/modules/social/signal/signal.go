package signal

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

const (
	moduleName     = "signal"
	minLookupDelay = 3 * time.Second
	cdnBase        = "https://storage.signal.org/"
	// hmacSecret is the key Signal uses for its hashed phone number lookup.
	hmacSecret = "signal-username-check"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Module struct {
	httpClient HTTPClient
	limiter    *core.RateLimiter
}

type Option func(*Module)

func New(opts ...Option) *Module {
	m := &Module{
		httpClient: core.NewHTTPClient(core.DefaultHTTPTimeout),
		limiter:    core.NewRateLimiter(minLookupDelay),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func WithHTTPClient(client HTTPClient) Option {
	return func(m *Module) {
		if client != nil {
			m.httpClient = client
		}
	}
}

func WithRateLimiter(limiter *core.RateLimiter) Option {
	return func(m *Module) {
		if limiter != nil {
			m.limiter = limiter
		}
	}
}

func (m *Module) Name() string        { return moduleName }
func (m *Module) RequiresAPIKey() bool { return false }
func (m *Module) Tier() core.ModuleTier { return core.TierPassive }
func (m *Module) ProxyAware() bool    { return true }

func (m *Module) Description() string {
	return "Signal registration check via hashed phone number lookup against Signal CDN."
}

func (m *Module) DryRun(ctx context.Context, number *core.PhoneNumber) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (m *Module) Run(ctx context.Context, number *core.PhoneNumber) (*core.ModuleResult, error) {
	if m.limiter != nil {
		if err := m.limiter.Wait(ctx, moduleName); err != nil {
			return nil, err
		}
	}

	account, err := m.check(ctx, number)
	if err != nil {
		return &core.ModuleResult{
			ModuleName: m.Name(),
			Status:     core.ModuleStatusError,
			Findings:   map[string]string{"error": err.Error()},
			Evidence:   []string{"Signal CDN check failed: " + err.Error()},
		}, nil
	}

	return &core.ModuleResult{
		ModuleName: m.Name(),
		Status:     core.ModuleStatusSuccess,
		Findings:   findings(account),
		Data:       account,
		Evidence:   []string{"Signal registration check via HMAC-SHA256 hashed phone number against storage.signal.org."},
	}, nil
}

func (m *Module) check(ctx context.Context, number *core.PhoneNumber) (*core.MessengerAccount, error) {
	phone := phoneE164(number)
	if phone == "" {
		return &core.MessengerAccount{Found: false, DataSource: "signal_cdn"}, nil
	}

	hash := hashPhone(phone)
	endpoint := cdnBase + hash

	reqCtx, cancel := context.WithTimeout(ctx, core.DefaultHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	core.SetDefaultHeaders(req)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("signal cdn: %w", err)
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()

	found := resp.StatusCode == http.StatusOK
	return &core.MessengerAccount{Found: found, DataSource: "signal_cdn"}, nil
}

// hashPhone computes HMAC-SHA256(phone, hmacSecret) and returns the base64 encoding.
func hashPhone(phone string) string {
	mac := hmac.New(sha256.New, []byte(hmacSecret))
	mac.Write([]byte(phone))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func findings(account *core.MessengerAccount) map[string]string {
	return map[string]string{
		"found":       strconv.FormatBool(account.Found),
		"data_source": account.DataSource,
	}
}

func phoneE164(number *core.PhoneNumber) string {
	if number == nil {
		return ""
	}
	for _, v := range []string{number.E164, number.RawInput, number.NationalNumber} {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
