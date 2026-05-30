package publicrecords

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/search"
	"github.com/KatrielMoses/PhoneAccess/internal/sources"
	"github.com/KatrielMoses/PhoneAccess/internal/storage"
	"gopkg.in/yaml.v3"
)

const (
	moduleName                 = "public_records"
	openCorporatesMonthlyLimit = 500
	openCorporatesQuotaKey     = "publicrecords.opencorporates"
	edgarHostKey               = "efts.sec.gov"
	openCorporatesHostKey      = "api.opencorporates.com"
	pacerHostKey               = "pcl.uscourts.gov"
	companiesHouseHostKey      = "api.company-information.service.gov.uk"
	fsmbHostKey                = "www.fsmb.org"
	propertySourceName         = "Google CSE"
)

//go:embed data/license_databases.yaml
var licenseDataFS embed.FS

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type LicenseDatabase struct {
	Name        string `yaml:"name" json:"name"`
	Category    string `yaml:"category" json:"category"`
	State       string `yaml:"state" json:"state"`
	SearchURL   string `yaml:"search_url" json:"search_url"`
	QueryParam  string `yaml:"query_param,omitempty" json:"query_param,omitempty"`
	LicenseType string `yaml:"license_type,omitempty" json:"license_type,omitempty"`
	NameRegex   string `yaml:"name_regex,omitempty" json:"name_regex,omitempty"`
	StatusRegex string `yaml:"status_regex,omitempty" json:"status_regex,omitempty"`
	ExtraRegex  string `yaml:"extra_regex,omitempty" json:"extra_regex,omitempty"`
}

type EdgarHit struct {
	EntityName     string `json:"entity_name"`
	FileDate       string `json:"file_date"`
	FormType       string `json:"form_type"`
	FilingURL      string `json:"filing_url"`
	PeriodOfReport string `json:"period_of_report,omitempty"`
}

type OfficerHit struct {
	OfficerName  string `json:"officer_name"`
	Company      string `json:"company"`
	Jurisdiction string `json:"jurisdiction"`
	Position     string `json:"position"`
	StartDate    string `json:"start_date,omitempty"`
	EndDate      string `json:"end_date,omitempty"`
	OfficerID    string `json:"officer_id,omitempty"`
}

type CompaniesHouseHit struct {
	OfficerName   string `json:"officer_name"`
	CompanyName   string `json:"company_name"`
	CompanyNumber string `json:"company_number,omitempty"`
	Appointment   string `json:"appointment,omitempty"`
	AppointedOn   string `json:"appointed_on,omitempty"`
	ResignedOn    string `json:"resigned_on,omitempty"`
	OfficerID     string `json:"officer_id,omitempty"`
	URL           string `json:"url,omitempty"`
}

type PacerHit struct {
	PartyName  string `json:"party_name"`
	CaseNumber string `json:"case_number"`
	Court      string `json:"court"`
	FilingDate string `json:"filing_date"`
	CaseType   string `json:"case_type"`
	URL        string `json:"url,omitempty"`
}

type LicenseHit struct {
	Name        string `json:"name"`
	LicenseType string `json:"license_type"`
	State       string `json:"state"`
	Status      string `json:"status"`
	URL         string `json:"url,omitempty"`
	Category    string `json:"category,omitempty"`
}

type PublicRecordsResult struct {
	EdgarHits          []EdgarHit          `json:"edgar_hits"`
	OpencorpHits       []OfficerHit        `json:"opencorp_hits"`
	CompaniesHouseHits []CompaniesHouseHit `json:"companies_house_hits,omitempty"`
	PacerHits          []PacerHit          `json:"pacer_hits"`
	LicenseHits        []LicenseHit        `json:"license_hits"`
	PropertyHints      []search.SearchHit  `json:"property_hints"`
	SourcesChecked     []string            `json:"sources_checked"`
	SourcesWithHits    []string            `json:"sources_with_hits"`
	SourceStatuses     map[string]string   `json:"source_statuses"`
	Names              []string            `json:"names,omitempty"`
	Skipped            bool                `json:"skipped,omitempty"`
	Note               string              `json:"note,omitempty"`
}

type apiKeys struct {
	OpenCorporates string
	PACERUsername  string
	PACERPassword  string
	GoogleCSEKey   string
	GoogleCSECX    string
}

type quotaStore interface {
	ConsumeMonthlyQuota(usageKey string, limit int, now time.Time) (bool, int, error)
}

type Module struct {
	httpClient        HTTPClient
	now               func() time.Time
	keyLoader         func() apiKeys
	quota             quotaStore
	licenseDBs        []LicenseDatabase
	knownCompanyHints []string
	limiter           *core.RateLimiter
}

type Option func(*Module)

func New(opts ...Option) *Module {
	m := &Module{
		httpClient: core.NewHTTPClient(core.DefaultHTTPTimeout),
		now:        func() time.Time { return time.Now().UTC() },
		keyLoader:  loadAPIKeys,
		licenseDBs: loadLicenseDatabases(),
		limiter:    core.NewRateLimiter(time.Second),
	}
	if store, err := storage.Open(""); err == nil {
		m.quota = store
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

func WithNow(now func() time.Time) Option {
	return func(m *Module) {
		if now != nil {
			m.now = now
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

func WithLicenseDatabases(dbs []LicenseDatabase) Option {
	return func(m *Module) {
		if len(dbs) > 0 {
			m.licenseDBs = append([]LicenseDatabase(nil), dbs...)
		}
	}
}

func WithKnownCompanyHints(hints []string) Option {
	return func(m *Module) {
		m.knownCompanyHints = append([]string(nil), hints...)
	}
}

func WithRateLimiter(limiter *core.RateLimiter) Option {
	return func(m *Module) {
		if limiter != nil {
			m.limiter = limiter
		}
	}
}

func WithAPIKeys(openCorporates, pacerUsername, pacerPassword, googleKey, googleCX string) Option {
	return func(m *Module) {
		prev := m.keyLoader
		m.keyLoader = func() apiKeys {
			keys := prev()
			keys.OpenCorporates = strings.TrimSpace(openCorporates)
			keys.PACERUsername = strings.TrimSpace(pacerUsername)
			keys.PACERPassword = strings.TrimSpace(pacerPassword)
			keys.GoogleCSEKey = strings.TrimSpace(googleKey)
			keys.GoogleCSECX = strings.TrimSpace(googleCX)
			return keys
		}
	}
}

func (m *Module) Name() string {
	return moduleName
}

func (m *Module) Description() string {
	return "Public records lookups across government and registry sources linked to a phone number."
}

func (m *Module) RequiresAPIKey() bool {
	return false
}

func (m *Module) Tier() core.ModuleTier {
	return core.TierActive
}

func (m *Module) DryRun(ctx context.Context, number *core.PhoneNumber) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (m *Module) RunPassive(ctx context.Context, number *core.PhoneNumber) (*core.ModuleResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	result := PublicRecordsResult{
		Skipped:        true,
		SourceStatuses: map[string]string{},
		Note:           "passive mode disables public records lookups",
	}
	for _, source := range m.sourcesChecked(number) {
		result.SourceStatuses[source] = "skipped"
	}
	return &core.ModuleResult{
		ModuleName: m.Name(),
		Status:     core.ModuleStatusSkipped,
		Findings:   findingsMap(result),
		Data:       result,
		Evidence:   []string{"Passive mode enabled; public records module made no network requests."},
	}, nil
}

func (m *Module) Run(ctx context.Context, number *core.PhoneNumber) (*core.ModuleResult, error) {
	result := PublicRecordsResult{
		SourceStatuses: map[string]string{},
		SourcesChecked: m.sourcesChecked(number),
	}
	keys := m.keyLoader()

	if hits, err := m.runEdgar(ctx, number); err != nil {
		result.SourceStatuses["SEC EDGAR"] = statusFromErr(err)
	} else {
		result.EdgarHits = hits
		m.recordHitStatus(&result, "SEC EDGAR", len(hits) > 0)
	}

	if hits, err := m.runOpenCorporates(ctx, number, keys); err != nil {
		result.SourceStatuses["OpenCorporates"] = statusFromErr(err)
	} else {
		result.OpencorpHits = hits
		m.recordHitStatus(&result, "OpenCorporates", len(hits) > 0)
	}

	companyHints := m.collectCompanyHints(&result)
	if hits, err := m.runCompaniesHouse(ctx, number, companyHints); err != nil {
		result.SourceStatuses["Companies House"] = statusFromErr(err)
	} else {
		result.CompaniesHouseHits = hits
		m.recordHitStatus(&result, "Companies House", len(hits) > 0)
	}

	if hits, err := m.runPACER(ctx, number, keys); err != nil {
		result.SourceStatuses["PACER"] = statusFromErr(err)
	} else {
		result.PacerHits = hits
		m.recordHitStatus(&result, "PACER", len(hits) > 0)
	}

	if hits, err := m.runLicenses(ctx, number); err != nil {
		result.SourceStatuses["Licenses"] = statusFromErr(err)
	} else {
		result.LicenseHits = hits
		m.recordHitStatus(&result, "Licenses", len(hits) > 0)
	}

	if hits, err := m.runPropertyHints(ctx, number, keys); err != nil {
		result.SourceStatuses["Property hints"] = statusFromErr(err)
	} else {
		result.PropertyHints = hits
		m.recordHitStatus(&result, "Property hints", len(hits) > 0)
	}

	result.Names = collectPublicRecordNames(result)
	if len(result.SourcesWithHits) == 0 && len(result.SourceStatuses) == 0 {
		result.Note = "no public records sources were eligible"
	}

	findings := findingsMap(result)
	status := core.ModuleStatusSuccess
	if len(result.SourcesWithHits) == 0 && allSkipped(result.SourceStatuses) {
		status = core.ModuleStatusSkipped
	}
	return &core.ModuleResult{
		ModuleName: m.Name(),
		Status:     status,
		Findings:   findings,
		Data:       result,
		Evidence:   evidenceFromStatuses(result.SourceStatuses),
	}, nil
}

func (m *Module) sourcesChecked(number *core.PhoneNumber) []string {
	sourcesChecked := []string{"SEC EDGAR", "OpenCorporates", "Companies House", "PACER", "Licenses", "Property hints"}
	return sourcesChecked
}

func (m *Module) recordHitStatus(result *PublicRecordsResult, source string, hit bool) {
	if result.SourceStatuses == nil {
		result.SourceStatuses = map[string]string{}
	}
	if hit {
		result.SourceStatuses[source] = "hit"
		result.SourcesWithHits = appendIfMissing(result.SourcesWithHits, source)
		return
	}
	if _, exists := result.SourceStatuses[source]; !exists {
		result.SourceStatuses[source] = "no results"
	}
}

func (m *Module) runEdgar(ctx context.Context, number *core.PhoneNumber) ([]EdgarHit, error) {
	if number == nil || strings.TrimSpace(number.E164) == "" {
		return nil, sources.ErrSkipped
	}
	if m.limiter != nil {
		if err := m.limiter.Wait(ctx, edgarHostKey); err != nil {
			return nil, err
		}
	}
	today := m.now().UTC().Format("2006-01-02")
	endpoint, _ := url.Parse("https://efts.sec.gov/LATEST/search-index")
	q := endpoint.Query()
	q.Set("q", fmt.Sprintf("\"%s\"", number.E164))
	q.Set("dateRange", "custom")
	q.Set("startdt", "2000-01-01")
	q.Set("enddt", today)
	q.Set("hits.hits._source", "period_of_report,entity_name,file_date,form_type")
	endpoint.RawQuery = q.Encode()

	body, err := m.get(ctx, endpoint.String(), edgarHostKey, nil)
	if err != nil {
		return nil, err
	}
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, err
	}
	return parseEdgarHits(decoded), nil
}

func (m *Module) runOpenCorporates(ctx context.Context, number *core.PhoneNumber, keys apiKeys) ([]OfficerHit, error) {
	if strings.TrimSpace(keys.OpenCorporates) == "" {
		return nil, sources.ErrSkipped
	}
	if m.quota != nil {
		ok, _, err := m.quota.ConsumeMonthlyQuota(openCorporatesQuotaKey, openCorporatesMonthlyLimit, m.now())
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("monthly OpenCorporates quota exhausted")
		}
	}
	if number == nil || strings.TrimSpace(number.E164) == "" {
		return nil, sources.ErrSkipped
	}
	endpoint, _ := url.Parse("https://api.opencorporates.com/v0.4/officers/search")
	q := endpoint.Query()
	q.Set("q", number.E164)
	q.Set("api_token", keys.OpenCorporates)
	endpoint.RawQuery = q.Encode()

	body, err := m.get(ctx, endpoint.String(), openCorporatesHostKey, nil)
	if err != nil {
		return nil, err
	}
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, err
	}
	return parseOpenCorporatesHits(decoded), nil
}

func (m *Module) runCompaniesHouse(ctx context.Context, number *core.PhoneNumber, companyHints []string) ([]CompaniesHouseHit, error) {
	if number == nil {
		return nil, sources.ErrSkipped
	}
	if !strings.HasPrefix(strings.TrimSpace(number.E164), "+44") && len(m.knownCompanyHints) == 0 {
		return nil, sources.ErrSkipped
	}
	candidates := append([]string(nil), companyHints...)
	candidates = append(candidates, m.knownCompanyHints...)
	candidates = uniqueStrings(candidates)
	if len(candidates) == 0 {
		return nil, sources.ErrSkipped
	}

	seen := map[string]bool{}
	var hits []CompaniesHouseHit
	for _, name := range candidates {
		searchURL, _ := url.Parse("https://api.company-information.service.gov.uk/search/officers")
		q := searchURL.Query()
		q.Set("q", name)
		searchURL.RawQuery = q.Encode()
		body, err := m.get(ctx, searchURL.String(), companiesHouseHostKey, nil)
		if err != nil {
			continue
		}
		officers := parseCompaniesHouseOfficerSearch(body)
		for _, officer := range officers {
			if strings.TrimSpace(officer.OfficerID) == "" {
				continue
			}
			appointmentsURL := fmt.Sprintf("https://api.company-information.service.gov.uk/officers/%s/appointments", url.PathEscape(officer.OfficerID))
			apptBody, err := m.get(ctx, appointmentsURL, companiesHouseHostKey, nil)
			if err != nil {
				continue
			}
			appointments := parseCompaniesHouseAppointments(apptBody, officer)
			for _, appointment := range appointments {
				key := strings.ToLower(strings.TrimSpace(appointment.OfficerID + "|" + appointment.CompanyNumber + "|" + appointment.CompanyName + "|" + appointment.AppointedOn))
				if seen[key] {
					continue
				}
				seen[key] = true
				hits = append(hits, appointment)
			}
		}
	}
	return hits, nil
}

func (m *Module) runPACER(ctx context.Context, number *core.PhoneNumber, keys apiKeys) ([]PacerHit, error) {
	if strings.TrimSpace(keys.PACERUsername) == "" || strings.TrimSpace(keys.PACERPassword) == "" {
		return nil, sources.ErrSkipped
	}
	if m.limiter != nil {
		if err := m.limiter.Wait(ctx, pacerHostKey); err != nil {
			return nil, err
		}
	}
	endpoint, _ := url.Parse("https://pcl.uscourts.gov/pcl/pages/search/results/parties.jsf")
	q := endpoint.Query()
	q.Set("q", number.E164)
	endpoint.RawQuery = q.Encode()
	body, err := m.get(ctx, endpoint.String(), pacerHostKey, map[string]string{
		"Authorization": basicAuth(keys.PACERUsername, keys.PACERPassword),
	})
	if err != nil {
		return nil, err
	}
	return parsePACERHits(body), nil
}

func (m *Module) runLicenses(ctx context.Context, number *core.PhoneNumber) ([]LicenseHit, error) {
	if number == nil || !strings.HasPrefix(strings.TrimSpace(number.E164), "+1") {
		return nil, sources.ErrSkipped
	}
	if len(m.licenseDBs) == 0 {
		return nil, sources.ErrSkipped
	}

	var hits []LicenseHit
	for _, db := range m.licenseDBs {
		if strings.TrimSpace(db.SearchURL) == "" {
			continue
		}
		searchURL := db.SearchURL
		if strings.Contains(searchURL, "{number}") {
			searchURL = strings.ReplaceAll(searchURL, "{number}", url.QueryEscape(number.E164))
		}
		if db.QueryParam != "" {
			parsed, err := url.Parse(searchURL)
			if err != nil {
				continue
			}
			query := parsed.Query()
			query.Set(db.QueryParam, number.E164)
			parsed.RawQuery = query.Encode()
			searchURL = parsed.String()
		}
		body, err := m.get(ctx, searchURL, hostFromURL(searchURL), nil)
		if err != nil {
			continue
		}
		hit := parseLicenseHit(db, body, searchURL)
		if hit != nil {
			hits = append(hits, *hit)
		}
	}
	return hits, nil
}

func (m *Module) runPropertyHints(ctx context.Context, number *core.PhoneNumber, keys apiKeys) ([]search.SearchHit, error) {
	if number == nil {
		return nil, sources.ErrSkipped
	}
	if strings.TrimSpace(keys.GoogleCSEKey) == "" || strings.TrimSpace(keys.GoogleCSECX) == "" {
		return nil, sources.ErrSkipped
	}
	query := fmt.Sprintf("%q site:*.gov assessor OR \"property tax\" OR \"parcel\"", number.E164)
	hits, err := search.GoogleCSESearch(ctx, m.httpClient, keys.GoogleCSEKey, keys.GoogleCSECX, query, "property_records", m.now())
	if err != nil {
		return nil, err
	}
	return hits, nil
}

func (m *Module) get(ctx context.Context, endpoint, limitKey string, headers map[string]string) ([]byte, error) {
	if m.limiter != nil {
		if err := m.limiter.Wait(ctx, limitKey); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	core.SetDefaultHeaders(req)
	req.Header.Set("Accept", "application/json, text/html, */*")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
}

func findingsMap(result PublicRecordsResult) map[string]string {
	return map[string]string{
		"skipped":           strconv.FormatBool(result.Skipped),
		"note":              result.Note,
		"sources_checked":   strings.Join(result.SourcesChecked, ", "),
		"sources_with_hits": strings.Join(result.SourcesWithHits, ", "),
	}
}

func evidenceFromStatuses(statuses map[string]string) []string {
	if len(statuses) == 0 {
		return nil
	}
	keys := make([]string, 0, len(statuses))
	for key := range statuses {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+": "+statuses[key])
	}
	return out
}

func collectPublicRecordNames(result PublicRecordsResult) []string {
	seen := map[string]string{}
	add := func(value string) {
		value = cleanValue(value)
		if value == "" {
			return
		}
		seen[strings.ToLower(value)] = value
	}
	for _, hit := range result.EdgarHits {
		add(hit.EntityName)
	}
	for _, hit := range result.OpencorpHits {
		add(hit.OfficerName)
		add(hit.Company)
	}
	for _, hit := range result.CompaniesHouseHits {
		add(hit.OfficerName)
		add(hit.CompanyName)
	}
	for _, hit := range result.PacerHits {
		add(hit.PartyName)
	}
	for _, hit := range result.LicenseHits {
		add(hit.Name)
	}
	return sortedMapValues(seen)
}

func (m *Module) collectCompanyHints(result *PublicRecordsResult) []string {
	var hints []string
	for _, hit := range result.EdgarHits {
		hints = append(hints, hit.EntityName)
	}
	for _, hit := range result.OpencorpHits {
		hints = append(hints, hit.Company)
	}
	for _, hit := range result.LicenseHits {
		hints = append(hints, hit.Name)
	}
	return uniqueStrings(hints)
}

func allSkipped(statuses map[string]string) bool {
	if len(statuses) == 0 {
		return false
	}
	for _, status := range statuses {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(status)), "skipped") {
			return false
		}
	}
	return true
}

func statusFromErr(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, sources.ErrSkipped) {
		return "skipped"
	}
	return "error: " + err.Error()
}

func appendIfMissing(values []string, want string) []string {
	for _, value := range values {
		if value == want {
			return values
		}
	}
	return append(values, want)
}

func uniqueStrings(values []string) []string {
	seen := map[string]string{}
	for _, value := range values {
		cleaned := cleanValue(value)
		if cleaned == "" {
			continue
		}
		seen[strings.ToLower(cleaned)] = cleaned
	}
	return sortedMapValues(seen)
}

func cleanValue(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`)
	return strings.Join(strings.Fields(value), " ")
}

func sortedMapValues(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, values[key])
	}
	return out
}

func loadAPIKeys() apiKeys {
	return apiKeys{
		OpenCorporates: strings.TrimSpace(sources.LoadKey("OPENCORPORATES_API_KEY")),
		PACERUsername:  strings.TrimSpace(sources.LoadKey("PACER_USERNAME")),
		PACERPassword:  strings.TrimSpace(sources.LoadKey("PACER_PASSWORD")),
		GoogleCSEKey:   strings.TrimSpace(sources.LoadKey("GOOGLE_CSE_API_KEY")),
		GoogleCSECX:    strings.TrimSpace(sources.LoadKey("GOOGLE_CSE_CX")),
	}
}

func loadLicenseDatabases() []LicenseDatabase {
	data, err := licenseDataFS.ReadFile("data/license_databases.yaml")
	if err != nil {
		return nil
	}
	var dbs []LicenseDatabase
	if err := yaml.Unmarshal(data, &dbs); err != nil {
		return nil
	}
	return dbs
}

var htmlTagPattern = regexp.MustCompile(`(?s)<[^>]+>`)

func parseEdgarHits(value any) []EdgarHit {
	var hits []EdgarHit
	walkJSON(value, func(node any) {
		object, ok := node.(map[string]any)
		if !ok {
			return
		}
		if _, ok := object["_source"]; !ok && object["entity_name"] == nil && object["file_date"] == nil {
			return
		}
		source := object
		if inner, ok := object["_source"].(map[string]any); ok {
			source = inner
		}
		entity := firstString(source, "entity_name", "entity", "company_name", "name")
		fileDate := firstString(source, "file_date", "filing_date", "date")
		formType := firstString(source, "form_type", "form", "type")
		period := firstString(source, "period_of_report", "period")
		filingURL := firstString(source, "filing_url", "url", "link")
		if filingURL == "" {
			filingURL = deriveFilingURL(source)
		}
		if entity == "" && filingURL == "" {
			return
		}
		hits = append(hits, EdgarHit{
			EntityName:     entity,
			FileDate:       fileDate,
			FormType:       formType,
			FilingURL:      filingURL,
			PeriodOfReport: period,
		})
	})
	return dedupeEdgarHits(hits)
}

func dedupeEdgarHits(hits []EdgarHit) []EdgarHit {
	seen := map[string]bool{}
	out := make([]EdgarHit, 0, len(hits))
	for _, hit := range hits {
		key := strings.ToLower(strings.TrimSpace(hit.EntityName + "|" + hit.FileDate + "|" + hit.FormType + "|" + hit.FilingURL))
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, hit)
	}
	return out
}

func deriveFilingURL(source map[string]any) string {
	accession := firstString(source, "accession_number", "accession_no", "accession", "accessionNumber")
	cik := firstString(source, "cik", "cik_number", "cikNumber")
	if accession == "" || cik == "" {
		return ""
	}
	compactAccession := strings.ReplaceAll(accession, "-", "")
	cik = onlyDigits(cik)
	if cik == "" || compactAccession == "" {
		return ""
	}
	return fmt.Sprintf("https://www.sec.gov/Archives/edgar/data/%s/%s/%s-index.htm", cik, compactAccession, compactAccession)
}

func parseOpenCorporatesHits(value any) []OfficerHit {
	var hits []OfficerHit
	walkJSON(value, func(node any) {
		object, ok := node.(map[string]any)
		if !ok {
			return
		}
		if officer, ok := object["officer"].(map[string]any); ok {
			object = officer
		}
		if firstString(object, "name", "officer_name", "full_name") == "" && firstString(object, "company", "company_name") == "" {
			return
		}
		hits = append(hits, OfficerHit{
			OfficerName:  cleanValue(firstString(object, "name", "officer_name", "full_name")),
			Company:      cleanValue(firstString(object, "company_name", "company", "organisation_name", "company_name")),
			Jurisdiction: cleanValue(firstString(object, "jurisdiction_code", "jurisdiction", "company_jurisdiction_code")),
			Position:     cleanValue(firstString(object, "position", "role", "title")),
			StartDate:    cleanValue(firstString(object, "start_date", "appointed_on")),
			EndDate:      cleanValue(firstString(object, "end_date", "resigned_on")),
			OfficerID:    officerIDFromObject(object),
		})
	})
	return dedupeOfficerHits(hits)
}

func dedupeOfficerHits(hits []OfficerHit) []OfficerHit {
	seen := map[string]bool{}
	out := make([]OfficerHit, 0, len(hits))
	for _, hit := range hits {
		key := strings.ToLower(strings.TrimSpace(hit.OfficerName + "|" + hit.Company + "|" + hit.Jurisdiction + "|" + hit.Position + "|" + hit.StartDate + "|" + hit.EndDate))
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, hit)
	}
	return out
}

func officerIDFromObject(object map[string]any) string {
	if id := firstString(object, "id", "officer_id", "officerId"); id != "" {
		return id
	}
	if links, ok := object["links"].(map[string]any); ok {
		if self := firstString(links, "self", "appointments"); self != "" {
			parts := strings.Split(strings.TrimRight(self, "/"), "/")
			if len(parts) > 0 {
				return parts[len(parts)-1]
			}
		}
	}
	if source, ok := object["source"].(map[string]any); ok {
		return officerIDFromObject(source)
	}
	return ""
}

func parseCompaniesHouseOfficerSearch(body []byte) []OfficerHit {
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil
	}
	var hits []OfficerHit
	walkJSON(decoded, func(node any) {
		object, ok := node.(map[string]any)
		if !ok {
			return
		}
		if firstString(object, "title", "name") == "" && officerIDFromObject(object) == "" {
			return
		}
		hits = append(hits, OfficerHit{
			OfficerName:  cleanValue(firstString(object, "title", "name")),
			Company:      cleanValue(firstString(object, "company_name", "company")),
			Jurisdiction: "GB",
			Position:     cleanValue(firstString(object, "position", "officer_role")),
			StartDate:    cleanValue(firstString(object, "start_date", "appointed_on")),
			EndDate:      cleanValue(firstString(object, "end_date", "resigned_on")),
			OfficerID:    officerIDFromObject(object),
		})
	})
	return dedupeOfficerHits(hits)
}

func parseCompaniesHouseAppointments(body []byte, officer OfficerHit) []CompaniesHouseHit {
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil
	}
	var hits []CompaniesHouseHit
	walkJSON(decoded, func(node any) {
		object, ok := node.(map[string]any)
		if !ok {
			return
		}
		companyName := firstString(object, "company_name", "name")
		companyNumber := firstString(object, "company_number", "companyNumber")
		appointedOn := firstString(object, "appointed_on", "appointedOn")
		resignedOn := firstString(object, "resigned_on", "resignedOn")
		role := firstString(object, "officer_role", "role", "appointment")
		if companyName == "" && companyNumber == "" && appointedOn == "" && role == "" {
			return
		}
		hit := CompaniesHouseHit{
			OfficerName:   officer.OfficerName,
			CompanyName:   cleanValue(companyName),
			CompanyNumber: cleanValue(companyNumber),
			Appointment:   cleanValue(role),
			AppointedOn:   cleanValue(appointedOn),
			ResignedOn:    cleanValue(resignedOn),
			OfficerID:     officer.OfficerID,
		}
		if hit.OfficerID != "" {
			hit.URL = fmt.Sprintf("https://api.company-information.service.gov.uk/officers/%s/appointments", url.PathEscape(hit.OfficerID))
		}
		hits = append(hits, hit)
	})
	return dedupeCompaniesHouseHits(hits)
}

func dedupeCompaniesHouseHits(hits []CompaniesHouseHit) []CompaniesHouseHit {
	seen := map[string]bool{}
	out := make([]CompaniesHouseHit, 0, len(hits))
	for _, hit := range hits {
		key := strings.ToLower(strings.TrimSpace(hit.OfficerName + "|" + hit.CompanyName + "|" + hit.CompanyNumber + "|" + hit.AppointedOn + "|" + hit.ResignedOn + "|" + hit.Appointment))
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, hit)
	}
	return out
}

func parsePACERHits(body []byte) []PacerHit {
	text := strings.TrimSpace(stripHTML(string(body)))
	if text == "" {
		return nil
	}
	lines := make([]string, 0)
	for _, line := range strings.Split(text, "\n") {
		line = cleanValue(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		lines = []string{text}
	}
	var hits []PacerHit
	for _, line := range lines {
		if !looksLikePACERLine(line) {
			continue
		}
		parts := splitFields(line)
		if len(parts) < 3 {
			continue
		}
		hit := PacerHit{
			PartyName:  parts[0],
			CaseNumber: pickPart(parts, 1),
			Court:      pickPart(parts, 2),
			FilingDate: pickPart(parts, 3),
			CaseType:   pickPart(parts, 4),
		}
		if hit.PartyName != "" || hit.CaseNumber != "" {
			hits = append(hits, hit)
		}
	}
	return hits
}

func parseLicenseHit(db LicenseDatabase, body []byte, sourceURL string) *LicenseHit {
	text := stripHTML(string(body))
	if strings.TrimSpace(text) == "" {
		return nil
	}
	name := regexCapture(text, db.NameRegex)
	status := regexCapture(text, db.StatusRegex)
	if name == "" {
		name = regexCapture(text, db.ExtraRegex)
	}
	if status == "" {
		status = inferStatus(text)
	}
	if name == "" && !strings.Contains(strings.ToLower(text), strings.ToLower(db.LicenseType)) {
		return nil
	}
	if name == "" {
		name = db.Name
	}
	return &LicenseHit{
		Name:        cleanValue(name),
		LicenseType: cleanValue(firstNonEmpty(db.LicenseType, db.Category)),
		State:       cleanValue(db.State),
		Status:      cleanValue(status),
		URL:         sourceURL,
		Category:    db.Category,
	}
}

func stripHTML(value string) string {
	value = htmlTagPattern.ReplaceAllString(value, "\n")
	value = strings.ReplaceAll(value, "&nbsp;", " ")
	value = strings.ReplaceAll(value, "&amp;", "&")
	return value
}

func regexCapture(value, pattern string) string {
	if strings.TrimSpace(pattern) == "" {
		return ""
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}
	match := re.FindStringSubmatch(value)
	if len(match) > 1 {
		return cleanValue(match[1])
	}
	if len(match) == 1 {
		return cleanValue(match[0])
	}
	return ""
}

func inferStatus(text string) string {
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "active"):
		return "active"
	case strings.Contains(lower, "expired"):
		return "expired"
	case strings.Contains(lower, "suspended"):
		return "suspended"
	case strings.Contains(lower, "revoked"):
		return "revoked"
	default:
		return ""
	}
}

func looksLikePACERLine(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "case") || strings.Contains(lower, "court") || strings.Contains(lower, "party")
}

func splitFields(line string) []string {
	fields := strings.FieldsFunc(line, func(r rune) bool {
		return r == '|' || r == ';' || r == '\t' || r == ','
	})
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		field = cleanValue(field)
		if field != "" {
			out = append(out, field)
		}
	}
	return out
}

func pickPart(parts []string, index int) string {
	if index < 0 || index >= len(parts) {
		return ""
	}
	return parts[index]
}

func firstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			switch v := value.(type) {
			case string:
				if strings.TrimSpace(v) != "" {
					return strings.TrimSpace(v)
				}
			case float64:
				return strconv.FormatFloat(v, 'f', -1, 64)
			case int:
				return strconv.Itoa(v)
			}
		}
	}
	for _, key := range keys {
		if value, ok := values[strings.ToLower(key)]; ok {
			if s, ok := value.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func walkJSON(value any, visit func(any)) {
	visit(value)
	switch v := value.(type) {
	case map[string]any:
		for _, child := range v {
			walkJSON(child, visit)
		}
	case []any:
		for _, child := range v {
			walkJSON(child, visit)
		}
	}
}

func basicAuth(username, password string) string {
	token := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(token))
}

func hostFromURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func onlyDigits(value string) string {
	var b strings.Builder
	for _, r := range value {
		if unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (m *Module) ProxyAware() bool { return true }
