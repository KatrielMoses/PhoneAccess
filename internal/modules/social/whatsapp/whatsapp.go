package whatsapp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
	"github.com/KatrielMoses/PhoneAccess/internal/media"
)

const (
	moduleName     = "whatsapp"
	sessionFile    = "whatsapp_session.db"
	setupHelp      = "run: phoneaccess whatsapp setup"
	disclaimer     = "This module uses your personal WhatsApp account. Use responsibly and within WhatsApp's terms of service."
	minLookupDelay = 5 * time.Second
	hourlyMax      = 20
)

type LookupClient interface {
	Lookup(ctx context.Context, number *core.PhoneNumber) (*core.MessengerAccount, error)
	Setup(ctx context.Context, stdout io.Writer) error
	HasSession() bool
}

type Module struct {
	client  LookupClient
	limiter *core.RateLimiter
	mu      sync.Mutex
	window  time.Time
	count   int
}

type Option func(*Module)

func New(opts ...Option) *Module {
	m := &Module{
		client:  liveClient{sessionPath: DefaultSessionPath},
		limiter: core.NewRateLimiter(minLookupDelay),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func WithClient(client LookupClient) Option {
	return func(m *Module) {
		if client != nil {
			m.client = client
		}
	}
}

func WithRateLimiter(limiter *core.RateLimiter) Option {
	return func(m *Module) { m.limiter = limiter }
}

func (m *Module) Name() string { return moduleName }
func (m *Module) Description() string {
	return "WhatsApp presence checks through the user's linked WhatsApp Web session."
}
func (m *Module) RequiresAPIKey() bool  { return false }
func (m *Module) Tier() core.ModuleTier { return core.TierActive }

func (m *Module) DryRun(ctx context.Context, number *core.PhoneNumber) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if !m.client.HasSession() {
		return errors.New("missing WhatsApp session; " + setupHelp + ". " + disclaimer)
	}
	if !m.reserveLookup(time.Now()) {
		return errors.New("WhatsApp hourly lookup cap exhausted; maximum 20 numbers per hour")
	}
	return nil
}

func (m *Module) Run(ctx context.Context, number *core.PhoneNumber) (*core.ModuleResult, error) {
	if m.limiter != nil {
		if err := m.limiter.Wait(ctx, moduleName); err != nil {
			return nil, err
		}
	}
	account, err := m.client.Lookup(ctx, number)
	if err != nil {
		return nil, err
	}
	if account == nil {
		account = &core.MessengerAccount{Found: false, DataSource: "whatsapp_web"}
	}
	account.DataSource = "whatsapp_web"
	if account.ProfilePhotoPath != "" && account.ProfilePhotoPHash == "" {
		if hash, err := media.PHashFile(account.ProfilePhotoPath); err == nil {
			account.ProfilePhotoPHash = hash
		}
	}
	return &core.ModuleResult{
		ModuleName: m.Name(),
		Status:     core.ModuleStatusSuccess,
		Findings:   findings(account),
		Data:       account,
		Evidence:   []string{disclaimer},
	}, nil
}

func (m *Module) reserveLookup(now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.window.IsZero() || now.Sub(m.window) >= time.Hour {
		m.window = now
		m.count = 0
	}
	if m.count >= hourlyMax {
		return false
	}
	m.count++
	return true
}

func Setup(ctx context.Context, stdout io.Writer) error {
	return New().client.Setup(ctx, stdout)
}

func DefaultSessionPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return sessionFile
	}
	return filepath.Join(home, ".phoneaccess", sessionFile)
}

func findings(account *core.MessengerAccount) map[string]string {
	return map[string]string{
		"found":               strconv.FormatBool(account.Found),
		"display_name":        account.DisplayName,
		"profile_photo_path":  account.ProfilePhotoPath,
		"profile_photo_phash": account.ProfilePhotoPHash,
		"about_bio":           account.AboutBio,
		"data_source":         account.DataSource,
	}
}

type liveClient struct {
	sessionPath func() string
}

func (c liveClient) HasSession() bool {
	info, err := os.Stat(c.sessionPath())
	return err == nil && !info.IsDir()
}

func (c liveClient) Lookup(ctx context.Context, number *core.PhoneNumber) (*core.MessengerAccount, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	return nil, errors.New("whatsmeow live client is not linked in this build; run with whatsmeow-enabled build or inject a LookupClient")
}

func (c liveClient) Setup(ctx context.Context, stdout io.Writer) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if stdout == nil {
		stdout = io.Discard
	}
	fmt.Fprintln(stdout, "WhatsApp setup")
	fmt.Fprintln(stdout, "Scan the QR code printed by a whatsmeow-enabled build to link your own account.")
	fmt.Fprintln(stdout, disclaimer)
	return core.EncryptSession(c.sessionPath(), []byte("placeholder session\n"))
}

func jidForNumber(number *core.PhoneNumber) string {
	e164 := ""
	if number != nil {
		e164 = firstNonEmpty(number.E164, number.RawInput, number.NationalNumber)
	}
	return strings.TrimPrefix(e164, "+") + "@s.whatsapp.net"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (m *Module) ProxyAware() bool { return false }
