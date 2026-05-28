package breach

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

const (
	moduleName = "breach"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Source interface {
	Name() string
	URL(number *core.PhoneNumber) string
	PrepareRequest(ctx context.Context, req *http.Request) error
	Parse(body []byte) SourceResult
}

type Module struct {
	httpClient HTTPClient
	limiter    *core.RateLimiter
	sources    []Source
}

type Option func(*Module)

type BreachEntry struct {
	Name        string   `json:"name"`
	Date        string   `json:"date,omitempty"`
	DataClasses []string `json:"data_classes_exposed,omitempty"`
	SourceAPI   string   `json:"source_api"`
	Emails      []string `json:"emails,omitempty"`
	Usernames   []string `json:"usernames,omitempty"`
}

type BreachResult struct {
	Found                   bool              `json:"found"`
	BreachCount             int               `json:"breach_count"`
	StealerCount            int               `json:"stealer_count"`
	CompromisedMachineCount int               `json:"compromised_machine_count"`
	CredentialsFound        bool              `json:"credentials_found"`
	SourcesChecked          []string          `json:"sources_checked"`
	Breaches                []BreachEntry     `json:"breaches"`
	DataClassesSeen         []string          `json:"data_classes_seen"`
	MostRecentBreach        string            `json:"most_recent_breach,omitempty"`
	SourceStatuses          map[string]string `json:"source_statuses"`
	Skipped                 bool              `json:"skipped,omitempty"`
	Note                    string            `json:"note,omitempty"`
}

type SourceResult struct {
	Source              string
	Breaches            []BreachEntry
	DataClasses         []string
	StealerCount        int
	CompromisedMachines int
	CredentialsFound    bool
	Available           bool
	Error               string
}

func New(opts ...Option) *Module {
	m := &Module{
		httpClient: core.NewHTTPClient(core.DefaultHTTPTimeout),
		limiter:    core.NewRateLimiter(time.Second),
		sources: []Source{
			xposedOrNotSource{},
			leakCheckSource{},
			hudsonRockSource{},
			snusbaseSource{},
			breachDirectorySource{},
			leakLookupSource{},
			scyllaSource{},
		},
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
		m.limiter = limiter
	}
}

func WithSources(sources ...Source) Option {
	return func(m *Module) {
		if len(sources) > 0 {
			m.sources = sources
		}
	}
}

func (m *Module) Name() string {
	return moduleName
}

func (m *Module) Description() string {
	return "Public breach and infostealer-log intelligence for phone numbers."
}

func (m *Module) RequiresAPIKey() bool {
	return false
}

func (m *Module) Tier() core.ModuleTier {
	return core.TierPassive
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

	result := BreachResult{
		Skipped:        true,
		SourcesChecked: sourceNames(m.sources),
		SourceStatuses: map[string]string{},
		Note:           "passive mode disables active breach and leak lookups",
	}
	for _, source := range result.SourcesChecked {
		result.SourceStatuses[source] = "skipped"
	}

	return &core.ModuleResult{
		ModuleName: m.Name(),
		Status:     core.ModuleStatusSkipped,
		Findings:   findingsFromBreachResult(result),
		Data:       result,
		Evidence:   []string{"Passive mode enabled; breach module made no network requests."},
	}, nil
}

func (m *Module) Run(ctx context.Context, number *core.PhoneNumber) (*core.ModuleResult, error) {
	results := make([]SourceResult, 0, len(m.sources))
	for _, source := range m.sources {
		results = append(results, m.querySource(ctx, source, number))
	}

	aggregated := aggregate(results)
	return &core.ModuleResult{
		ModuleName: m.Name(),
		Status:     core.ModuleStatusSuccess,
		Findings:   findingsFromBreachResult(aggregated),
		Data:       aggregated,
		Evidence:   evidenceFromStatuses(aggregated.SourceStatuses),
	}, nil
}

func (m *Module) querySource(ctx context.Context, source Source, number *core.PhoneNumber) SourceResult {
	result := SourceResult{
		Source: source.Name(),
	}

	ctx = core.WithPhoneNumber(ctx, number)

	endpoint := source.URL(number)
	parsed, err := url.Parse(endpoint)
	if err != nil {
		result.Error = "invalid source URL"
		return result
	}

	if m.limiter != nil {
		if err := m.limiter.Wait(ctx, parsed.Hostname()); err != nil {
			result.Error = err.Error()
			return result
		}
	}

	requestCtx, cancel := context.WithTimeout(ctx, core.DefaultHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	core.SetDefaultHeaders(req)
	req.Header.Set("Accept", "application/json")
	if err := source.PrepareRequest(ctx, req); err != nil {
		result.Available = false
		result.Error = err.Error()
		return result
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		result.Available = true
		return result
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		result.Error = fmt.Sprintf("http status %d", resp.StatusCode)
		return result
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		result.Error = err.Error()
		return result
	}

	parsedResult := source.Parse(body)
	parsedResult.Source = source.Name()
	parsedResult.Available = true
	for i := range parsedResult.Breaches {
		if parsedResult.Breaches[i].SourceAPI == "" {
			parsedResult.Breaches[i].SourceAPI = source.Name()
		}
	}
	return parsedResult
}

func aggregate(results []SourceResult) BreachResult {
	out := BreachResult{
		Breaches:       make([]BreachEntry, 0),
		SourceStatuses: map[string]string{},
	}
	seenBreaches := map[string]int{}
	dataClasses := map[string]string{}
	var mostRecent *time.Time

	for _, result := range results {
		out.SourcesChecked = append(out.SourcesChecked, result.Source)
		if !result.Available {
			status := "unavailable"
			if strings.TrimSpace(result.Error) != "" {
				status += ": " + result.Error
			}
			out.SourceStatuses[result.Source] = status
			continue
		}

		hit := len(result.Breaches) > 0 || result.StealerCount > 0 || result.CredentialsFound
		if hit {
			out.SourceStatuses[result.Source] = "hit"
		} else {
			out.SourceStatuses[result.Source] = "no results"
		}

		out.StealerCount += result.StealerCount
		out.CompromisedMachineCount += result.CompromisedMachines
		out.CredentialsFound = out.CredentialsFound || result.CredentialsFound
		for _, class := range result.DataClasses {
			addDataClass(dataClasses, class)
		}
		for _, entry := range result.Breaches {
			entry.Name = cleanValue(entry.Name)
			if entry.Name == "" {
				continue
			}
			entry.Date = normalizeDateString(entry.Date)
			entry.DataClasses = normalizeClasses(entry.DataClasses)
			entry.Emails = normalizeStrings(entry.Emails)
			entry.Usernames = normalizeStrings(entry.Usernames)
			for _, class := range entry.DataClasses {
				addDataClass(dataClasses, class)
			}
			key := strings.ToLower(entry.Name + "|" + entry.Date)
			if idx, ok := seenBreaches[key]; ok {
				out.Breaches[idx].Emails = normalizeStrings(append(out.Breaches[idx].Emails, entry.Emails...))
				out.Breaches[idx].Usernames = normalizeStrings(append(out.Breaches[idx].Usernames, entry.Usernames...))
				continue
			}
			seenBreaches[key] = len(out.Breaches)
			out.Breaches = append(out.Breaches, entry)
			if parsed, ok := parseFlexibleDate(entry.Date); ok && (mostRecent == nil || parsed.After(*mostRecent)) {
				copyTime := parsed
				mostRecent = &copyTime
			}
		}
	}

	sort.SliceStable(out.Breaches, func(i, j int) bool {
		left, leftOK := parseFlexibleDate(out.Breaches[i].Date)
		right, rightOK := parseFlexibleDate(out.Breaches[j].Date)
		switch {
		case leftOK && rightOK:
			return left.After(right)
		case leftOK:
			return true
		case rightOK:
			return false
		default:
			return out.Breaches[i].Name < out.Breaches[j].Name
		}
	})

	out.BreachCount = len(out.Breaches)
	out.DataClassesSeen = sortedMapValues(dataClasses)
	if mostRecent != nil {
		out.MostRecentBreach = mostRecent.Format("2006-01-02")
	}
	out.Found = out.BreachCount > 0 || out.StealerCount > 0 || out.CredentialsFound
	return out
}

func findingsFromBreachResult(result BreachResult) map[string]string {
	return map[string]string{
		"found":                strconv.FormatBool(result.Found),
		"breach_count":         strconv.Itoa(result.BreachCount),
		"stealer_count":        strconv.Itoa(result.StealerCount),
		"compromised_machines": strconv.Itoa(result.CompromisedMachineCount),
		"credentials_found":    strconv.FormatBool(result.CredentialsFound),
		"sources_checked":      strings.Join(result.SourcesChecked, ", "),
		"breaches":             formatBreaches(result.Breaches),
		"data_classes_seen":    strings.Join(result.DataClassesSeen, ", "),
		"most_recent_breach":   result.MostRecentBreach,
		"source_statuses":      joinStatuses(result.SourceStatuses),
		"skipped":              strconv.FormatBool(result.Skipped),
		"note":                 result.Note,
	}
}

func formatBreaches(entries []BreachEntry) string {
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		classes := strings.Join(entry.DataClasses, ", ")
		line := entry.Name
		if entry.Date != "" {
			line += " " + entry.Date
		}
		if len(entry.Emails) > 0 {
			line += " " + strings.Join(entry.Emails, ",")
		}
		if len(entry.Usernames) > 0 {
			line += " " + strings.Join(entry.Usernames, ",")
		}
		if classes != "" {
			line += " [" + classes + "]"
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func evidenceFromStatuses(statuses map[string]string) []string {
	if len(statuses) == 0 {
		return nil
	}
	names := make([]string, 0, len(statuses))
	for name := range statuses {
		names = append(names, name)
	}
	sort.Strings(names)
	evidence := make([]string, 0, len(names))
	for _, name := range names {
		evidence = append(evidence, name+": "+statuses[name])
	}
	return evidence
}

func joinStatuses(statuses map[string]string) string {
	names := make([]string, 0, len(statuses))
	for name := range statuses {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+"="+statuses[name])
	}
	return strings.Join(parts, "; ")
}

func sourceNames(sources []Source) []string {
	names := make([]string, 0, len(sources))
	for _, source := range sources {
		names = append(names, source.Name())
	}
	return names
}

type xposedOrNotSource struct{}

func (xposedOrNotSource) Name() string {
	return "XposedOrNot"
}

func (xposedOrNotSource) URL(number *core.PhoneNumber) string {
	endpoint, _ := url.Parse("https://api.xposedornot.com/v1/breach-analytics")
	query := endpoint.Query()
	query.Set("phone", e164(number))
	endpoint.RawQuery = query.Encode()
	return endpoint.String()
}

func (xposedOrNotSource) PrepareRequest(ctx context.Context, req *http.Request) error {
	return nil
}

func (xposedOrNotSource) Parse(body []byte) SourceResult {
	var response xposedResponse
	if err := json.Unmarshal(body, &response); err != nil || response.hasNotFoundError() {
		return SourceResult{}
	}

	entries := make([]BreachEntry, 0)
	for _, detail := range response.ExposedBreaches.BreachesDetails {
		name := firstNonEmpty(detail.Breach, detail.BreachID, detail.Name, detail.Title)
		if name == "" {
			continue
		}
		entries = append(entries, BreachEntry{
			Name:        name,
			Date:        firstNonEmpty(detail.XposedDate, detail.BreachedDate, detail.Date),
			DataClasses: splitClasses(detail.XposedData, detail.ExposedData),
			SourceAPI:   "XposedOrNot",
		})
	}
	for _, detail := range response.ExposedBreachesList {
		name := firstNonEmpty(detail.BreachID, detail.Breach, detail.Name, detail.Title)
		if name == "" {
			continue
		}
		entries = append(entries, BreachEntry{
			Name:        name,
			Date:        firstNonEmpty(detail.BreachedDate, detail.XposedDate, detail.Date),
			DataClasses: splitClasses(detail.XposedData, detail.ExposedData),
			SourceAPI:   "XposedOrNot",
		})
	}

	return SourceResult{
		Breaches:    entries,
		DataClasses: response.BreachMetrics.XposedData.Classes(),
	}
}

type leakCheckSource struct{}

func (leakCheckSource) Name() string {
	return "LeakCheck"
}

func (leakCheckSource) URL(number *core.PhoneNumber) string {
	endpoint, _ := url.Parse("https://leakcheck.io/api/public")
	query := endpoint.Query()
	query.Set("key", "")
	query.Set("type", "phone")
	query.Set("query", lookupDigits(number))
	endpoint.RawQuery = query.Encode()
	return endpoint.String()
}

func (leakCheckSource) PrepareRequest(ctx context.Context, req *http.Request) error {
	return nil
}

func (leakCheckSource) Parse(body []byte) SourceResult {
	var response leakCheckResponse
	if err := json.Unmarshal(body, &response); err != nil || response.hasNotFoundError() {
		return SourceResult{}
	}

	entries := make([]BreachEntry, 0)
	dataClasses := normalizeClasses(response.Fields)
	for _, item := range response.Result {
		sourceEntry := item.SourceEntry()
		name := firstNonEmpty(item.Name, sourceEntry.Name, sourceEntry.Source)
		if name == "" {
			name = "LeakCheck result"
		}
		classes := splitClasses("", firstNonEmptySlice(item.Fields, item.Types, item.DataTypes, sourceEntry.Fields, response.Fields))
		entries = append(entries, BreachEntry{
			Name:        name,
			Date:        firstNonEmpty(item.Date, item.BreachDate, sourceEntry.Date, sourceEntry.BreachDate),
			DataClasses: classes,
			SourceAPI:   "LeakCheck",
		})
		dataClasses = append(dataClasses, classes...)
	}
	for _, source := range response.SourceEntries() {
		entries = append(entries, source)
		dataClasses = append(dataClasses, source.DataClasses...)
	}

	if len(entries) == 0 && truthyFound(response.Found) {
		entries = append(entries, BreachEntry{
			Name:        "LeakCheck public index",
			DataClasses: normalizeClasses(dataClasses),
			SourceAPI:   "LeakCheck",
		})
	}

	return SourceResult{
		Breaches:    entries,
		DataClasses: dataClasses,
	}
}

type hudsonRockSource struct{}

func (hudsonRockSource) Name() string {
	return "HudsonRock Cavalier"
}

func (hudsonRockSource) URL(number *core.PhoneNumber) string {
	endpoint, _ := url.Parse("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-phone")
	query := endpoint.Query()
	query.Set("phone", e164(number))
	endpoint.RawQuery = query.Encode()
	return endpoint.String()
}

func (hudsonRockSource) PrepareRequest(ctx context.Context, req *http.Request) error {
	return nil
}

func (hudsonRockSource) Parse(body []byte) SourceResult {
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil || responseLooksNotFound(raw) {
		return SourceResult{}
	}

	stealers := maxInt(
		intField(raw, "stealers_count", "stealer_count", "total_stealers", "total", "count"),
		arrayLengthField(raw, "stealers", "stealer_logs", "data"),
	)
	machines := maxInt(
		intField(raw, "compromised_machines", "compromised_machine_count", "computers_count", "total_computers"),
		uniqueMachineCount(raw),
	)
	credentialsFound := boolField(raw, "credentials_found", "has_credentials") || arrayLengthField(raw, "credentials", "passwords", "top_passwords") > 0

	return SourceResult{
		StealerCount:        stealers,
		CompromisedMachines: machines,
		CredentialsFound:    credentialsFound,
	}
}

type xposedResponse struct {
	Error           string `json:"Error"`
	Message         string `json:"message"`
	Status          string `json:"status"`
	ExposedBreaches struct {
		BreachesDetails []xposedBreach `json:"breaches_details"`
	} `json:"ExposedBreaches"`
	ExposedBreachesList []xposedBreach `json:"exposedBreaches"`
	BreachMetrics       struct {
		XposedData classBreakdown `json:"xposed_data"`
	} `json:"BreachMetrics"`
}

func (r xposedResponse) hasNotFoundError() bool {
	text := strings.ToLower(firstNonEmpty(r.Error, r.Message, r.Status))
	return strings.Contains(text, "not found") || text == "error"
}

type xposedBreach struct {
	Breach       string   `json:"breach"`
	BreachID     string   `json:"breachID"`
	Name         string   `json:"name"`
	Title        string   `json:"title"`
	Date         string   `json:"date"`
	XposedDate   string   `json:"xposed_date"`
	BreachedDate string   `json:"breachedDate"`
	XposedData   string   `json:"xposed_data"`
	ExposedData  []string `json:"exposedData"`
}

type classBreakdown json.RawMessage

func (c classBreakdown) Classes() []string {
	if len(c) == 0 {
		return nil
	}
	var raw any
	if err := json.Unmarshal([]byte(c), &raw); err != nil {
		return nil
	}
	classes := map[string]string{}
	collectClasses(raw, classes)
	return sortedMapValues(classes)
}

type leakCheckResponse struct {
	Error   any             `json:"error"`
	Success bool            `json:"success"`
	Found   any             `json:"found"`
	Message string          `json:"message"`
	Fields  []string        `json:"fields"`
	Result  []leakCheckItem `json:"result"`
	Sources json.RawMessage `json:"sources"`
}

func (r leakCheckResponse) hasNotFoundError() bool {
	text := strings.ToLower(r.Message)
	if strings.Contains(text, "not found") || strings.Contains(text, "no results") {
		return true
	}
	if s, ok := r.Error.(string); ok && strings.EqualFold(s, "true") && !truthyFound(r.Found) {
		return true
	}
	if b, ok := r.Error.(bool); ok && b && !truthyFound(r.Found) {
		return true
	}
	return false
}

func (r leakCheckResponse) SourceEntries() []BreachEntry {
	if len(r.Sources) == 0 || string(r.Sources) == "null" {
		return nil
	}
	var names []string
	if err := json.Unmarshal(r.Sources, &names); err == nil {
		entries := make([]BreachEntry, 0, len(names))
		for _, name := range names {
			if cleanValue(name) != "" {
				entries = append(entries, BreachEntry{Name: name, DataClasses: normalizeClasses(r.Fields), SourceAPI: "LeakCheck"})
			}
		}
		return entries
	}
	var objects []leakCheckSourceEntry
	if err := json.Unmarshal(r.Sources, &objects); err == nil {
		entries := make([]BreachEntry, 0, len(objects))
		for _, source := range objects {
			name := firstNonEmpty(source.Name, source.Source)
			if cleanValue(name) == "" {
				continue
			}
			entries = append(entries, BreachEntry{
				Name:        name,
				Date:        firstNonEmpty(source.Date, source.BreachDate),
				DataClasses: normalizeClasses(firstNonEmptySlice(source.Fields, r.Fields)),
				SourceAPI:   "LeakCheck",
			})
		}
		return entries
	}
	return nil
}

type leakCheckItem struct {
	Name       string          `json:"name"`
	Source     json.RawMessage `json:"source"`
	Date       string          `json:"date"`
	BreachDate string          `json:"breach_date"`
	Fields     []string        `json:"fields"`
	Types      []string        `json:"types"`
	DataTypes  []string        `json:"data_types"`
}

func (i leakCheckItem) SourceEntry() leakCheckSourceEntry {
	if len(i.Source) == 0 || string(i.Source) == "null" {
		return leakCheckSourceEntry{}
	}
	var name string
	if err := json.Unmarshal(i.Source, &name); err == nil {
		return leakCheckSourceEntry{Name: name}
	}
	var source leakCheckSourceEntry
	if err := json.Unmarshal(i.Source, &source); err == nil {
		return source
	}
	return leakCheckSourceEntry{}
}

type leakCheckSourceEntry struct {
	Name       string   `json:"name"`
	Source     string   `json:"source"`
	Date       string   `json:"date"`
	BreachDate string   `json:"breach_date"`
	Fields     []string `json:"fields"`
}

func e164(number *core.PhoneNumber) string {
	if number == nil {
		return ""
	}
	return firstNonEmpty(number.E164, number.RawInput, number.NationalNumber)
}

func lookupDigits(number *core.PhoneNumber) string {
	return onlyDigits(e164(number))
}

func splitClasses(value string, extras []string) []string {
	parts := make([]string, 0)
	for _, chunk := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ';' || r == ',' || r == '|'
	}) {
		parts = append(parts, chunk)
	}
	parts = append(parts, extras...)
	return normalizeClasses(parts)
}

func normalizeClasses(values []string) []string {
	seen := map[string]string{}
	for _, value := range values {
		addDataClass(seen, value)
	}
	return sortedMapValues(seen)
}

func normalizeStrings(values []string) []string {
	seen := map[string]string{}
	for _, value := range values {
		value = cleanValue(value)
		if value != "" {
			seen[strings.ToLower(value)] = value
		}
	}
	return sortedMapValues(seen)
}

func addDataClass(seen map[string]string, value string) {
	value = cleanValue(value)
	if value == "" {
		return
	}
	key := strings.ToLower(value)
	seen[key] = value
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstNonEmptySlice(values ...[]string) []string {
	for _, value := range values {
		if len(value) > 0 {
			return value
		}
	}
	return nil
}

func onlyDigits(value string) string {
	var builder strings.Builder
	for _, r := range value {
		if r >= '0' && r <= '9' {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func normalizeDateString(value string) string {
	value = cleanValue(value)
	if value == "" {
		return ""
	}
	if parsed, ok := parseFlexibleDate(value); ok {
		return parsed.Format("2006-01-02")
	}
	return value
}

func parseFlexibleDate(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02",
		"2006-1-2",
		"2006",
		"Jan 2, 2006",
		"January 2, 2006",
		"Mon, 02 Jan 2006 15:04:05 MST",
	} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			if layout == "2006" {
				return time.Date(parsed.Year(), 1, 1, 0, 0, 0, 0, time.UTC), true
			}
			return parsed, true
		}
	}
	return time.Time{}, false
}

func truthyFound(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case float64:
		return v > 0
	case int:
		return v > 0
	case string:
		v = strings.ToLower(strings.TrimSpace(v))
		return v == "true" || v == "yes" || (v != "" && v != "0" && v != "false")
	default:
		return false
	}
}

func collectClasses(value any, seen map[string]string) {
	switch v := value.(type) {
	case map[string]any:
		if name, ok := v["name"].(string); ok {
			name = strings.TrimPrefix(name, "data_")
			addDataClass(seen, name)
		}
		for _, child := range v {
			collectClasses(child, seen)
		}
	case []any:
		for _, child := range v {
			collectClasses(child, seen)
		}
	case string:
		for _, part := range splitClasses(v, nil) {
			addDataClass(seen, part)
		}
	}
}

func responseLooksNotFound(value any) bool {
	switch v := value.(type) {
	case map[string]any:
		for _, key := range []string{"error", "message", "status"} {
			if text, ok := v[key].(string); ok {
				lower := strings.ToLower(text)
				if strings.Contains(lower, "not found") || strings.Contains(lower, "no results") {
					return true
				}
			}
		}
		if found, ok := v["found"]; ok && !truthyFound(found) {
			return true
		}
	}
	return false
}

func intField(value any, names ...string) int {
	best := 0
	walkJSON(value, func(node any) {
		object, ok := node.(map[string]any)
		if !ok {
			return
		}
		for _, name := range names {
			if got := numberValue(object[name]); got > best {
				best = got
			}
		}
	})
	return best
}

func arrayLengthField(value any, names ...string) int {
	best := 0
	walkJSON(value, func(node any) {
		object, ok := node.(map[string]any)
		if !ok {
			return
		}
		for _, name := range names {
			if arr, ok := object[name].([]any); ok && len(arr) > best {
				best = len(arr)
			}
		}
	})
	return best
}

func boolField(value any, names ...string) bool {
	found := false
	walkJSON(value, func(node any) {
		object, ok := node.(map[string]any)
		if !ok {
			return
		}
		for _, name := range names {
			if value, ok := object[name].(bool); ok && value {
				found = true
			}
		}
	})
	return found
}

func uniqueMachineCount(value any) int {
	machines := map[string]bool{}
	walkJSON(value, func(node any) {
		object, ok := node.(map[string]any)
		if !ok {
			return
		}
		for _, key := range []string{"computer_name", "machine_id", "hwid", "ip"} {
			if text, ok := object[key].(string); ok && strings.TrimSpace(text) != "" {
				machines[key+":"+text] = true
				return
			}
		}
	})
	return len(machines)
}

func numberValue(value any) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		i, _ := strconv.Atoi(v)
		return i
	default:
		return 0
	}
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

func maxInt(values ...int) int {
	best := 0
	for _, value := range values {
		if value > best {
			best = value
		}
	}
	return best
}
