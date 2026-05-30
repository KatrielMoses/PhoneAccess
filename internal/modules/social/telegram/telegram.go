package telegram

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/config"
	"github.com/KatrielMoses/PhoneAccess/internal/core"
	"github.com/KatrielMoses/PhoneAccess/internal/media"
)

const (
	moduleName     = "telegram"
	appIDKey       = "TELEGRAM_APP_ID"
	appHashKey     = "TELEGRAM_APP_HASH"
	sessionFile    = "telegram_session.json"
	setupHelp      = "configure TELEGRAM_APP_ID and TELEGRAM_APP_HASH, then run: phoneaccess telegram setup"
	minLookupDelay = 3 * time.Second
)

type LookupClient interface {
	Lookup(ctx context.Context, number *core.PhoneNumber) (*core.MessengerAccount, error)
	Setup(ctx context.Context, stdin io.Reader, stdout io.Writer) error
}

type Module struct {
	client    LookupClient
	keyLoader func() credentials
	limiter   *core.RateLimiter
}

type credentials struct {
	appID   string
	appHash string
}

type Option func(*Module)

func New(opts ...Option) *Module {
	m := &Module{
		keyLoader: loadCredentials,
		limiter:   core.NewRateLimiter(minLookupDelay),
	}
	m.client = liveClient{creds: m.keyLoader, sessionPath: DefaultSessionPath}
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

func WithCredentials(appID, appHash string) Option {
	return func(m *Module) {
		m.keyLoader = func() credentials { return credentials{appID: appID, appHash: appHash} }
		m.client = liveClient{creds: m.keyLoader, sessionPath: DefaultSessionPath}
	}
}

func WithRateLimiter(limiter *core.RateLimiter) Option {
	return func(m *Module) { m.limiter = limiter }
}

func (m *Module) Name() string { return moduleName }
func (m *Module) Description() string {
	return "Telegram account discovery using the official MTProto contacts import flow."
}
func (m *Module) RequiresAPIKey() bool  { return true }
func (m *Module) Tier() core.ModuleTier { return core.TierActive }

func (m *Module) DryRun(ctx context.Context, number *core.PhoneNumber) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	creds := m.keyLoader()
	if strings.TrimSpace(creds.appID) == "" || strings.TrimSpace(creds.appHash) == "" {
		return errors.New("missing TELEGRAM_APP_ID or TELEGRAM_APP_HASH; " + setupHelp)
	}
	return nil
}

func (m *Module) Run(ctx context.Context, number *core.PhoneNumber) (*core.ModuleResult, error) {
	if m.limiter != nil {
		if err := m.limiter.Wait(ctx, moduleName); err != nil {
			return nil, err
		}
	}

	account, err := m.lookupWithFloodRetry(ctx, number)
	if err != nil {
		return nil, err
	}
	if account == nil {
		account = &core.MessengerAccount{Found: false, DataSource: "telegram_mtproto"}
	}
	account.DataSource = "telegram_mtproto"
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
		Evidence:   []string{"Telegram contacts.ImportContacts lookup via official MTProto API."},
	}, nil
}

func (m *Module) lookupWithFloodRetry(ctx context.Context, number *core.PhoneNumber) (*core.MessengerAccount, error) {
	account, err := m.client.Lookup(ctx, number)
	wait, ok := floodWait(err)
	if !ok {
		return account, err
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
	}
	return m.client.Lookup(ctx, number)
}

func Setup(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	return New().client.Setup(ctx, stdin, stdout)
}

func DefaultSessionPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return sessionFile
	}
	return filepath.Join(home, ".phoneaccess", sessionFile)
}

func loadCredentials() credentials {
	out := credentials{
		appID:   strings.TrimSpace(os.Getenv(appIDKey)),
		appHash: strings.TrimSpace(os.Getenv(appHashKey)),
	}
	store, err := config.NewDefaultStore()
	if err != nil {
		return out
	}
	cfg, err := store.Load()
	if err != nil {
		return out
	}
	if value := firstConfigured(cfg.APIKeys, appIDKey, "telegram_app_id"); value != "" {
		out.appID = value
	}
	if value := firstConfigured(cfg.APIKeys, appHashKey, "telegram_app_hash"); value != "" {
		out.appHash = value
	}
	return out
}

func firstConfigured(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(values[key]); value != "" {
			return value
		}
	}
	return ""
}

func findings(account *core.MessengerAccount) map[string]string {
	return map[string]string{
		"found":               strconv.FormatBool(account.Found),
		"display_name":        account.DisplayName,
		"username":            account.Username,
		"bio":                 account.Bio,
		"last_seen_bucket":    account.LastSeenBucket,
		"account_id":          account.AccountID,
		"profile_photo_path":  account.ProfilePhotoPath,
		"profile_photo_phash": account.ProfilePhotoPHash,
		"data_source":         account.DataSource,
	}
}

var floodPattern = regexp.MustCompile(`(?i)FLOOD_WAIT_?(\d+)`)

func floodWait(err error) (time.Duration, bool) {
	if err == nil {
		return 0, false
	}
	match := floodPattern.FindStringSubmatch(err.Error())
	if len(match) < 2 {
		return 0, false
	}
	seconds, convErr := strconv.Atoi(match[1])
	if convErr != nil || seconds <= 0 {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

type liveClient struct {
	creds       func() credentials
	sessionPath func() string
}

func (c liveClient) Lookup(ctx context.Context, number *core.PhoneNumber) (*core.MessengerAccount, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	return nil, errors.New("telegram live MTProto client is not linked in this build; run with gotd/td-enabled build or inject a LookupClient")
}

func (c liveClient) Setup(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	creds := c.creds()
	if strings.TrimSpace(creds.appID) == "" || strings.TrimSpace(creds.appHash) == "" {
		return errors.New("missing TELEGRAM_APP_ID or TELEGRAM_APP_HASH; register an app at https://my.telegram.org and save the values with phoneaccess keys set")
	}
	if stdout == nil {
		stdout = io.Discard
	}
	fmt.Fprintln(stdout, "Telegram setup")
	fmt.Fprintln(stdout, "Enter your Telegram phone number, then the OTP when prompted by a gotd/td-enabled build.")
	if stdin != nil {
		scanner := bufio.NewScanner(stdin)
		_ = scanner.Scan()
	}
	return core.EncryptSession(c.sessionPath(), []byte("{}\n"))
}

func (m *Module) ProxyAware() bool { return false }
