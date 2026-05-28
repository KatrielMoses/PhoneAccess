package truecaller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/config"
	"github.com/KatrielMoses/PhoneAccess/internal/core"
	"github.com/KatrielMoses/PhoneAccess/internal/sources"
)

const (
	moduleName            = "truecaller"
	defaultNoneUEndpoint  = "https://search5-noneu.truecaller.com/v2/search"
	defaultEUEndpoint     = "https://search5-eu.truecaller.com/v2/search"
	installationIDKeyName = "TRUECALLER_INSTALLATION_ID"
	truecallerUserAgent   = "Truecaller/13.37.6 (Android; 12; en)"
	maxDailyLookups       = 100
	warnLookupThreshold   = 80
	sessionExpiredMessage = "Truecaller session expired \u2014 re-register the app and update TRUECALLER_INSTALLATION_ID."
	unofficialDisclaimer  = "Truecaller integration uses an unofficial session token. This is unsupported by Truecaller and may violate their Terms of Service. Use is the responsibility of the operator. Session tokens are obtained by registering the official Truecaller app on your own device."
)

var errMissingInstallationID = errors.New("missing TRUECALLER_INSTALLATION_ID")

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type quotaStore interface {
	Load() (map[string]quotaEntry, error)
	Save(map[string]quotaEntry) error
}

type quotaEntry struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

type fileQuotaStore struct {
	path string
	mu   sync.Mutex
}

type memoryQuotaStore struct {
	mu   sync.Mutex
	data map[string]quotaEntry
}

type Module struct {
	httpClient     HTTPClient
	installationID string
	noneUEndpoint  string
	euEndpoint     string
	quota          quotaStore
	now            func() time.Time
}

type Option func(*Module)

type Result struct {
	Source      string   `json:"source,omitempty"`
	Name        string   `json:"name,omitempty"`
	Score       float64  `json:"score,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	NumberType  string   `json:"number_type,omitempty"`
	City        string   `json:"city,omitempty"`
	CountryCode string   `json:"country_code,omitempty"`
	TimeZone    string   `json:"time_zone,omitempty"`
	Emails      []string `json:"emails,omitempty"`
	Company     string   `json:"company,omitempty"`
	JobTitle    string   `json:"job_title,omitempty"`
	CallerType  string   `json:"caller_type,omitempty"`
}

func New(opts ...Option) *Module {
	m := &Module{
		httpClient:     core.NewHTTPClient(core.DefaultHTTPTimeout),
		installationID: strings.TrimSpace(sources.LoadKey(installationIDKeyName, "truecaller_installation_id")),
		noneUEndpoint:  defaultNoneUEndpoint,
		euEndpoint:     defaultEUEndpoint,
		quota:          defaultQuotaStore(),
		now:            func() time.Time { return time.Now().UTC() },
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

func WithInstallationID(installationID string) Option {
	return func(m *Module) {
		m.installationID = strings.TrimSpace(installationID)
	}
}

func WithEndpoints(nonEU, eu string) Option {
	return func(m *Module) {
		if strings.TrimSpace(nonEU) != "" {
			m.noneUEndpoint = strings.TrimRight(nonEU, "/")
		}
		if strings.TrimSpace(eu) != "" {
			m.euEndpoint = strings.TrimRight(eu, "/")
		}
	}
}

func WithQuotaStore(store quotaStore) Option {
	return func(m *Module) {
		if store != nil {
			m.quota = store
		}
	}
}

func WithNow(now func() time.Time) Option {
	return func(m *Module) {
		if now != nil {
			m.now = now
		}
	}
}

func (m *Module) Name() string {
	return moduleName
}

func (m *Module) Description() string {
	return "Unofficial Truecaller session-token scanner for rich identity pivots."
}

func (m *Module) RequiresAPIKey() bool {
	return true
}

func (m *Module) Tier() core.ModuleTier {
	return core.TierActive
}

func (m *Module) DryRun(ctx context.Context, number *core.PhoneNumber) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if strings.TrimSpace(m.installationID) == "" {
		return fmt.Errorf("%w; %s. %s", errMissingInstallationID, setupHint(), unofficialDisclaimer)
	}
	return nil
}

func (m *Module) Run(ctx context.Context, number *core.PhoneNumber) (*core.ModuleResult, error) {
	if strings.TrimSpace(m.installationID) == "" {
		return nil, fmt.Errorf("%w; %s. %s", errMissingInstallationID, setupHint(), unofficialDisclaimer)
	}
	if err := m.consumeLookup(); err != nil {
		return nil, err
	}

	endpoint := m.endpointFor(number)
	var response truecallerResponse
	if err := m.getJSON(ctx, endpoint, &response); err != nil {
		return nil, err
	}

	entry := firstEntry(response.Data)
	if entry == nil {
		return &core.ModuleResult{
			ModuleName: m.Name(),
			Status:     core.ModuleStatusSuccess,
			Findings: map[string]string{
				"source": "Truecaller",
				"found":  "false",
			},
			Data:     Result{Source: "Truecaller"},
			Evidence: []string{unofficialDisclaimer},
		}, nil
	}

	result := buildResult(entry)
	return &core.ModuleResult{
		ModuleName: m.Name(),
		Status:     core.ModuleStatusSuccess,
		Findings:   result.findings(),
		Data:       result,
		Evidence:   []string{"Truecaller session token lookup completed.", unofficialDisclaimer},
	}, nil
}

func (m *Module) endpointFor(number *core.PhoneNumber) string {
	base := m.noneUEndpoint
	if isEUTruecallerNumber(lookupNumber(number)) {
		base = m.euEndpoint
	}
	endpoint, _ := url.Parse(strings.TrimRight(base, "/"))
	query := endpoint.Query()
	query.Set("q", lookupNumber(number))
	query.Set("countryCode", strings.ToUpper(strings.TrimSpace(countryCode(number))))
	query.Set("type", "4")
	query.Set("locAddr", "")
	query.Set("placement", "SEARCHRESULTS,cl")
	query.Set("encoding", "json")
	endpoint.RawQuery = query.Encode()
	return endpoint.String()
}

func (m *Module) getJSON(ctx context.Context, endpoint string, target any) error {
	fetch := func(ctx context.Context) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		core.SetDefaultHeaders(req)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", truecallerUserAgent)
		req.Header.Set("Authorization", "Bearer "+m.installationID)
		req.Header.Set("X-Timestamp", fmt.Sprintf("%d", m.now().UnixMilli()))

		resp, err := m.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, errors.New(sessionExpiredMessage)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("http status %d", resp.StatusCode)
		}
		return io.ReadAll(resp.Body)
	}

	cache := sources.ResponseCacheFromContext(ctx)
	var (
		data []byte
		err  error
	)
	if cache != nil {
		data, err = cache.GetOrFetch(ctx, endpoint, fetch)
	} else {
		data, err = fetch(ctx)
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

func (m *Module) consumeLookup() error {
	if m.quota == nil {
		m.quota = memoryQuotaStoreWithData(nil)
	}
	day := m.now().UTC().Format("2006-01-02")
	key := sessionKey(m.installationID)
	count, err := quotaIncrement(m.quota, key, day)
	if err != nil {
		return err
	}
	if count == warnLookupThreshold {
		log.Printf("warning: Truecaller session has reached %d lookups for %s", warnLookupThreshold, day)
	}
	return nil
}

func buildResult(entry *truecallerEntry) Result {
	result := Result{
		Source:      "Truecaller",
		Name:        strings.TrimSpace(entry.Name),
		Score:       entry.Score,
		Tags:        normalizeStrings(entry.Tags),
		NumberType:  "",
		City:        firstAddressField(entry, func(a truecallerAddress) string { return a.City }),
		CountryCode: firstAddressField(entry, func(a truecallerAddress) string { return a.CountryCode }),
		TimeZone:    firstAddressField(entry, func(a truecallerAddress) string { return a.TimeZone }),
		Emails:      normalizeStrings(entry.InternetAddresses),
		Company:     strings.TrimSpace(entry.Company),
		JobTitle:    strings.TrimSpace(entry.JobTitle),
	}
	if len(entry.Phones) > 0 {
		result.NumberType = normalizeLineType(entry.Phones[0].NumberType)
	}
	if len(result.Tags) == 0 {
		result.Tags = []string{}
	}
	return result
}

func (r Result) findings() map[string]string {
	return map[string]string{
		"source":       "Truecaller",
		"found":        strconvFormatBool(r.Name != "" || r.City != "" || len(r.Emails) > 0),
		"name":         r.Name,
		"city":         r.City,
		"country_code": r.CountryCode,
		"confidence":   fmt.Sprintf("%.2f", r.Score),
		"score":        fmt.Sprintf("%.2f", r.Score),
		"number_type":  r.NumberType,
		"company":      r.Company,
		"job_title":    r.JobTitle,
		"tags":         strings.Join(r.Tags, ", "),
		"email_pivots": strings.Join(r.Emails, ", "),
		"time_zone":    r.TimeZone,
		"caller_type":  r.CallerType,
	}
}

func setupHint() string {
	return "register the official Truecaller app on your own device and set TRUECALLER_INSTALLATION_ID"
}

func defaultQuotaStore() quotaStore {
	store, err := config.NewDefaultStore()
	if err != nil {
		return memoryQuotaStoreWithData(nil)
	}
	path := filepath.Join(filepath.Dir(store.Path()), "truecaller_quota.json")
	return &fileQuotaStore{path: path}
}

func (s *fileQuotaStore) Load() (map[string]quotaEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]quotaEntry{}, nil
		}
		return nil, err
	}
	var entries map[string]quotaEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	if entries == nil {
		entries = map[string]quotaEntry{}
	}
	return entries, nil
}

func (s *fileQuotaStore) Save(entries map[string]quotaEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}

func memoryQuotaStoreWithData(entries map[string]quotaEntry) *memoryQuotaStore {
	if entries == nil {
		entries = map[string]quotaEntry{}
	}
	return &memoryQuotaStore{data: entries}
}

func (m *memoryQuotaStore) Load() (map[string]quotaEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]quotaEntry, len(m.data))
	for key, value := range m.data {
		out[key] = value
	}
	return out, nil
}

func (m *memoryQuotaStore) Save(entries map[string]quotaEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = make(map[string]quotaEntry, len(entries))
	for key, value := range entries {
		m.data[key] = value
	}
	return nil
}

func quotaIncrement(store quotaStore, key, day string) (int, error) {
	entries, err := store.Load()
	if err != nil {
		return 0, err
	}
	entry := entries[key]
	if entry.Date != day {
		entry.Date = day
		entry.Count = 0
	}
	if entry.Count >= maxDailyLookups {
		return entry.Count, fmt.Errorf("Truecaller daily limit reached: %d lookups per day per session", maxDailyLookups)
	}
	entry.Count++
	entries[key] = entry
	if err := store.Save(entries); err != nil {
		return 0, err
	}
	return entry.Count, nil
}

func sessionKey(installationID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(installationID)))
	return hex.EncodeToString(sum[:])
}

func firstEntry(entries []truecallerEntry) *truecallerEntry {
	if len(entries) == 0 {
		return nil
	}
	return &entries[0]
}

func lookupNumber(number *core.PhoneNumber) string {
	if number == nil {
		return ""
	}
	return firstNonEmpty(number.E164, number.RawInput, number.NationalNumber)
}

func countryCode(number *core.PhoneNumber) string {
	if number == nil {
		return ""
	}
	return strings.TrimSpace(number.CountryAlpha2)
}

func isEUTruecallerNumber(e164 string) bool {
	for _, prefix := range []string{"+31", "+32", "+33", "+34", "+39", "+40", "+41", "+43", "+44", "+45", "+46", "+47", "+48", "+49", "+351", "+352", "+353", "+354", "+355", "+356", "+357", "+358", "+359", "+370", "+371", "+372", "+373", "+374", "+375", "+376", "+377", "+378", "+380", "+381", "+382", "+385", "+386", "+387", "+389"} {
		if strings.HasPrefix(e164, prefix) {
			return true
		}
	}
	return false
}

func normalizeLineType(value string) string {
	switch strings.ToLower(strings.TrimSpace(strings.ReplaceAll(value, "_", "-"))) {
	case "mobile":
		return "mobile"
	case "landline":
		return "landline"
	case "fixedvoip", "nonfixedvoip", "voip":
		return "voip"
	case "tollfree", "toll-free":
		return "toll-free"
	case "premiumrate", "premium-rate":
		return "premium-rate"
	default:
		return strings.TrimSpace(value)
	}
}

func normalizeStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if seen[strings.ToLower(value)] {
			continue
		}
		seen[strings.ToLower(value)] = true
		out = append(out, value)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func strconvFormatBool(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func firstAddressField(entry *truecallerEntry, pick func(truecallerAddress) string) string {
	if entry == nil || len(entry.Addresses) == 0 {
		return ""
	}
	return strings.TrimSpace(pick(entry.Addresses[0]))
}

type truecallerResponse struct {
	Data []truecallerEntry `json:"data"`
}

type truecallerEntry struct {
	Name              string              `json:"name"`
	Score             float64             `json:"score"`
	Tags              []string            `json:"tags"`
	Phones            []truecallerPhone   `json:"phones"`
	Addresses         []truecallerAddress `json:"addresses"`
	InternetAddresses []string            `json:"internetAddresses"`
	Company           string              `json:"company"`
	JobTitle          string              `json:"jobTitle"`
}

type truecallerPhone struct {
	NumberType string `json:"numberType"`
}

type truecallerAddress struct {
	City        string `json:"city"`
	CountryCode string `json:"countryCode"`
	TimeZone    string `json:"timeZone"`
}
