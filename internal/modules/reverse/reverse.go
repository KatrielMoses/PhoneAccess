package reverse

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/config"
	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

const (
	moduleName    = "reverse"
	openCNAMKey   = "OPENCNAM_SID"
	maxBodyBytes  = 2 * 1024 * 1024
	maxGoogleHits = 5
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Source interface {
	Name() string
	URL(number *core.PhoneNumber) string
	Accept() string
	Parse(body []byte, number *core.PhoneNumber) SourceResult
}

type Module struct {
	httpClient HTTPClient
	limiter    *core.RateLimiter
	keyLoader  func() string
	sources    func() []Source
}

type Option func(*Module)

type ReverseResult struct {
	NameHint        string            `json:"name_hint,omitempty"`
	NameConfidence  string            `json:"name_confidence,omitempty"`
	LocationHint    string            `json:"location_hint,omitempty"`
	SourcesChecked  []string          `json:"sources_checked"`
	SourcesWithHits []string          `json:"sources_with_hits"`
	RawHits         []ReverseHit      `json:"raw_hits"`
	WaybackHits     []WaybackHit      `json:"wayback_hits,omitempty"`
	PivotEmails     []string          `json:"pivot_emails,omitempty"`
	PivotUsernames  []string          `json:"pivot_usernames,omitempty"`
	SourceStatuses  map[string]string `json:"source_statuses"`
	Skipped         bool              `json:"skipped,omitempty"`
	Note            string            `json:"note,omitempty"`
}

type ReverseHit struct {
	Source     string `json:"source"`
	RawText    string `json:"raw_text"`
	Confidence string `json:"confidence"`
}

type WaybackHit struct {
	Source    string `json:"source"`
	URL       string `json:"url"`
	FirstSeen string `json:"first_seen"`
}

type SourceResult struct {
	Source     string
	Name       string
	Location   string
	RawText    string
	Confidence string
	Emails     []string
	Usernames  []string
	Available  bool
	Error      string
}

func New(opts ...Option) *Module {
	m := &Module{
		httpClient: core.NewHTTPClient(core.DefaultHTTPTimeout),
		limiter:    core.NewRateLimiter(2 * time.Second),
		keyLoader:  loadOpenCNAMSID,
	}
	m.sources = func() []Source {
		sources := []Source{
			truecallerSource{},
			googleDorkSource{},
			zabaSearchSource{},
		}
		if sid := strings.TrimSpace(m.keyLoader()); sid != "" {
			sources = append(sources, openCNAMSource{sid: sid})
		}
		return sources
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

func WithOpenCNAMSID(sid string) Option {
	return func(m *Module) {
		m.keyLoader = func() string {
			return sid
		}
	}
}

func WithSources(sources ...Source) Option {
	return func(m *Module) {
		m.sources = func() []Source {
			return sources
		}
	}
}

func (m *Module) Name() string {
	return moduleName
}

func (m *Module) Description() string {
	return "Public reverse lookup and identity pivot discovery."
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

	result := ReverseResult{
		Skipped:         true,
		SourcesChecked:  sourceNames(m.sources()),
		SourcesWithHits: []string{},
		RawHits:         []ReverseHit{},
		PivotEmails:     []string{},
		PivotUsernames:  []string{},
		SourceStatuses:  map[string]string{},
		Note:            "passive mode disables active reverse lookup requests",
	}
	for _, source := range result.SourcesChecked {
		result.SourceStatuses[source] = "skipped"
	}

	return &core.ModuleResult{
		ModuleName: m.Name(),
		Status:     core.ModuleStatusSkipped,
		Findings:   findingsFromReverseResult(result),
		Data:       result,
		Evidence:   []string{"Passive mode enabled; reverse lookup module made no network requests."},
	}, nil
}

func (m *Module) Run(ctx context.Context, number *core.PhoneNumber) (*core.ModuleResult, error) {
	results := make([]SourceResult, 0)
	for _, source := range m.sources() {
		results = append(results, m.querySource(ctx, source, number))
	}

	aggregated := aggregate(results)
	aggregated.WaybackHits = m.collectWayback(ctx, number)
	return &core.ModuleResult{
		ModuleName: m.Name(),
		Status:     core.ModuleStatusSuccess,
		Findings:   findingsFromReverseResult(aggregated),
		Data:       aggregated,
		Evidence:   evidenceFromStatuses(aggregated.SourceStatuses),
	}, nil
}

func (m *Module) querySource(ctx context.Context, source Source, number *core.PhoneNumber) SourceResult {
	result := SourceResult{Source: source.Name()}

	endpoint := source.URL(number)
	if strings.TrimSpace(endpoint) == "" {
		result.Available = true
		return result
	}
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
	req.Header.Set("Accept", source.Accept())

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

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		result.Error = err.Error()
		return result
	}

	parsedResult := source.Parse(body, number)
	parsedResult.Source = source.Name()
	parsedResult.Available = true
	return parsedResult
}

func aggregate(results []SourceResult) ReverseResult {
	out := ReverseResult{
		SourcesChecked:  []string{},
		SourcesWithHits: []string{},
		RawHits:         []ReverseHit{},
		PivotEmails:     []string{},
		PivotUsernames:  []string{},
		SourceStatuses:  map[string]string{},
	}
	nameVotes := map[string]map[string]bool{}
	nameDisplay := map[string]string{}
	nameConfidence := map[string]string{}
	emails := map[string]string{}
	usernames := map[string]string{}
	locationVotes := map[string]int{}
	locationDisplay := map[string]string{}

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

		result.Name = cleanName(result.Name)
		result.Location = cleanText(result.Location)
		result.RawText = cleanText(result.RawText)
		result.Emails = normalizeEmailList(result.Emails)
		result.Usernames = normalizeUsernameList(result.Usernames)

		hit := result.Name != "" || result.Location != "" || len(result.Emails) > 0 || len(result.Usernames) > 0
		if !hit {
			out.SourceStatuses[result.Source] = "no results"
			continue
		}

		out.SourcesWithHits = append(out.SourcesWithHits, result.Source)
		out.SourceStatuses[result.Source] = "hit"
		out.RawHits = append(out.RawHits, ReverseHit{
			Source:     result.Source,
			RawText:    result.RawText,
			Confidence: firstNonEmpty(result.Confidence, "low"),
		})

		if result.Name != "" {
			key := normalizeName(result.Name)
			if nameVotes[key] == nil {
				nameVotes[key] = map[string]bool{}
				nameDisplay[key] = result.Name
				nameConfidence[key] = firstNonEmpty(result.Confidence, "low")
			}
			nameVotes[key][result.Source] = true
			if confidenceRank(result.Confidence) > confidenceRank(nameConfidence[key]) {
				nameConfidence[key] = result.Confidence
				nameDisplay[key] = result.Name
			}
		}
		if result.Location != "" {
			key := strings.ToLower(result.Location)
			locationVotes[key]++
			locationDisplay[key] = result.Location
		}
		for _, email := range result.Emails {
			emails[strings.ToLower(email)] = email
		}
		for _, username := range result.Usernames {
			usernames[strings.ToLower(strings.TrimPrefix(username, "@"))] = strings.TrimPrefix(username, "@")
		}
	}

	out.NameHint, out.NameConfidence = chooseName(nameVotes, nameDisplay, nameConfidence)
	out.LocationHint = chooseLocation(locationVotes, locationDisplay)
	out.PivotEmails = sortedMapValues(emails)
	out.PivotUsernames = sortedMapValues(usernames)
	return out
}

func chooseName(votes map[string]map[string]bool, display map[string]string, confidence map[string]string) (string, string) {
	if len(votes) == 0 {
		return "", ""
	}
	keys := make([]string, 0, len(votes))
	for key := range votes {
		keys = append(keys, key)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		leftSources, rightSources := len(votes[keys[i]]), len(votes[keys[j]])
		if leftSources == rightSources {
			leftRank, rightRank := confidenceRank(confidence[keys[i]]), confidenceRank(confidence[keys[j]])
			if leftRank == rightRank {
				return display[keys[i]] < display[keys[j]]
			}
			return leftRank > rightRank
		}
		return leftSources > rightSources
	})
	best := keys[0]
	if len(votes[best]) >= 2 {
		return display[best], "high"
	}
	if confidenceRank(confidence[best]) >= confidenceRank("medium") {
		return display[best], "medium"
	}
	return display[best], "low"
}

func chooseLocation(votes map[string]int, display map[string]string) string {
	if len(votes) == 0 {
		return ""
	}
	keys := make([]string, 0, len(votes))
	for key := range votes {
		keys = append(keys, key)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		if votes[keys[i]] == votes[keys[j]] {
			return display[keys[i]] < display[keys[j]]
		}
		return votes[keys[i]] > votes[keys[j]]
	})
	return display[keys[0]]
}

func findingsFromReverseResult(result ReverseResult) map[string]string {
	return map[string]string{
		"name_hint":         result.NameHint,
		"name_confidence":   result.NameConfidence,
		"location_hint":     result.LocationHint,
		"sources_checked":   strings.Join(result.SourcesChecked, ", "),
		"sources_with_hits": strings.Join(result.SourcesWithHits, ", "),
		"raw_hits":          formatRawHits(result.RawHits),
		"wayback_hits":      formatWaybackHits(result.WaybackHits),
		"pivot_emails":      strings.Join(result.PivotEmails, ", "),
		"pivot_usernames":   strings.Join(result.PivotUsernames, ", "),
		"source_statuses":   joinStatuses(result.SourceStatuses),
		"skipped":           strconv.FormatBool(result.Skipped),
		"note":              result.Note,
	}
}

func formatRawHits(hits []ReverseHit) string {
	lines := make([]string, 0, len(hits))
	for _, hit := range hits {
		line := hit.Source
		if hit.Confidence != "" {
			line += " [" + hit.Confidence + "]"
		}
		if hit.RawText != "" {
			line += ": " + hit.RawText
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func formatWaybackHits(hits []WaybackHit) string {
	lines := make([]string, 0, len(hits))
	for _, hit := range hits {
		line := hit.Source
		if hit.FirstSeen != "" {
			line += " " + hit.FirstSeen
		}
		if hit.URL != "" {
			line += " <" + hit.URL + ">"
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

func (m *Module) collectWayback(ctx context.Context, number *core.PhoneNumber) []WaybackHit {
	hits := []WaybackHit{}
	seen := map[string]bool{}
	for _, source := range m.sources() {
		targetURL := strings.TrimSpace(source.URL(number))
		if targetURL == "" {
			continue
		}
		firstSeen, err := m.waybackFirstSeen(ctx, targetURL)
		if err != nil || firstSeen == "" {
			continue
		}
		key := strings.ToLower(source.Name() + "|" + targetURL + "|" + firstSeen)
		if seen[key] {
			continue
		}
		seen[key] = true
		hits = append(hits, WaybackHit{
			Source:    source.Name(),
			URL:       targetURL,
			FirstSeen: firstSeen,
		})
	}
	return hits
}

func (m *Module) waybackFirstSeen(ctx context.Context, targetURL string) (string, error) {
	endpoint, _ := url.Parse("https://web.archive.org/cdx/search/cdx")
	query := endpoint.Query()
	query.Set("url", targetURL)
	query.Set("output", "json")
	query.Set("fl", "timestamp,statuscode")
	query.Set("limit", "5")
	endpoint.RawQuery = query.Encode()

	if m.limiter != nil {
		if err := m.limiter.Wait(ctx, endpoint.Hostname()); err != nil {
			return "", err
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", err
	}
	core.SetDefaultHeaders(req)
	req.Header.Set("Accept", "application/json")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("wayback http status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return "", err
	}
	var decoded [][]string
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", err
	}
	if len(decoded) <= 1 {
		return "", nil
	}
	best := ""
	for _, row := range decoded[1:] {
		if len(row) == 0 {
			continue
		}
		ts := strings.TrimSpace(row[0])
		if ts == "" {
			continue
		}
		if best == "" || ts < best {
			best = ts
		}
	}
	return best, nil
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

type truecallerSource struct{}

func (truecallerSource) Name() string {
	return "Truecaller"
}

func (truecallerSource) URL(number *core.PhoneNumber) string {
	country := strings.ToLower(strings.TrimSpace(number.CountryAlpha2))
	if country == "" && number.CountryCode > 0 {
		country = strconv.Itoa(number.CountryCode)
	}
	return fmt.Sprintf("https://www.truecaller.com/search/%s/%s", url.PathEscape(country), url.PathEscape(nationalNumber(number)))
}

func (truecallerSource) Accept() string {
	return "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
}

func (truecallerSource) Parse(body []byte, number *core.PhoneNumber) SourceResult {
	text := htmlText(body)
	lower := strings.ToLower(text)
	name := firstNonEmpty(
		firstJSONValue(body, "name", "alternateName"),
		extractNameWithContext(text),
		extractNameFromTitle(body),
	)
	location := firstNonEmpty(
		firstJSONValue(body, "addressLocality", "addressRegion", "location"),
		extractLocationWithContext(text),
	)
	if name == "" && strings.Contains(lower, "log in") && strings.Contains(lower, "truecaller") {
		return SourceResult{}
	}
	raw := compactRaw(firstNonEmpty(name, location, text))
	if name != "" {
		raw = compactRaw(strings.Join(nonEmpty([]string{name, location}), " - "))
	}
	return SourceResult{
		Name:       name,
		Location:   location,
		RawText:    raw,
		Confidence: "medium",
	}
}

type googleDorkSource struct{}

func (googleDorkSource) Name() string {
	return "Google"
}

func (googleDorkSource) URL(number *core.PhoneNumber) string {
	endpoint, _ := url.Parse("https://www.google.com/search")
	query := endpoint.Query()
	query.Set("q", fmt.Sprintf("%s (name OR owner OR profile OR contact)", core.SearchQueryPhrase(number)))
	query.Set("num", strconv.Itoa(maxGoogleHits))
	endpoint.RawQuery = query.Encode()
	return endpoint.String()
}

func (googleDorkSource) Accept() string {
	return "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
}

func (googleDorkSource) Parse(body []byte, number *core.PhoneNumber) SourceResult {
	segments := googleSegments(body)
	digits := onlyDigits(e164(number))
	result := SourceResult{Confidence: "low"}
	for _, segment := range segments {
		if !mentionsNumber(segment, number, digits) {
			continue
		}
		if result.Name == "" {
			result.Name = extractNameWithContext(segment)
			if result.Name == "" {
				result.Name = inferCapitalizedName(segment)
			}
		}
		result.Emails = append(result.Emails, extractEmails(segment)...)
		result.Usernames = append(result.Usernames, extractUsernames(segment)...)
		if result.RawText == "" {
			result.RawText = compactRaw(segment)
		}
	}
	result.Emails = normalizeEmailList(result.Emails)
	result.Usernames = normalizeUsernameList(result.Usernames)
	return result
}

type zabaSearchSource struct{}

func (zabaSearchSource) Name() string {
	return "ZabaSearch"
}

func (zabaSearchSource) URL(number *core.PhoneNumber) string {
	if !strings.EqualFold(numberCountryAlpha2(number), "US") {
		return ""
	}
	return fmt.Sprintf("https://www.zabasearch.com/phone/%s", url.PathEscape(rawLocal(number)))
}

func (zabaSearchSource) Accept() string {
	return "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
}

func (zabaSearchSource) Parse(body []byte, number *core.PhoneNumber) SourceResult {
	text := htmlText(body)
	if text == "" {
		return SourceResult{}
	}
	name := firstNonEmpty(extractNameWithContext(text), inferCapitalizedName(text))
	location := extractLocationWithContext(text)
	raw := compactRaw(firstNonEmpty(name, location, text))
	return SourceResult{
		Name:       name,
		Location:   location,
		RawText:    raw,
		Confidence: "low",
	}
}

type openCNAMSource struct {
	sid string
}

func (s openCNAMSource) Name() string {
	return "OpenCNAM"
}

func (s openCNAMSource) URL(number *core.PhoneNumber) string {
	endpoint, _ := url.Parse("https://api.opencnam.com/v2/phone/" + url.PathEscape(e164(number)))
	query := endpoint.Query()
	query.Set("format", "json")
	query.Set("account_sid", s.sid)
	endpoint.RawQuery = query.Encode()
	return endpoint.String()
}

func (openCNAMSource) Accept() string {
	return "application/json"
}

func (openCNAMSource) Parse(body []byte, number *core.PhoneNumber) SourceResult {
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return SourceResult{}
	}
	name := ""
	switch v := raw.(type) {
	case map[string]any:
		for _, key := range []string{"name", "cnam", "caller_name"} {
			if text, ok := v[key].(string); ok {
				name = text
				break
			}
		}
	case string:
		name = v
	}
	name = cleanName(name)
	if name == "" || strings.EqualFold(name, "unknown") {
		return SourceResult{}
	}
	return SourceResult{
		Name:       name,
		RawText:    name,
		Confidence: "medium",
	}
}

var (
	htmlTagPattern      = regexp.MustCompile(`(?s)<[^>]+>`)
	scriptPattern       = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	stylePattern        = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	titlePattern        = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	jsonStringPattern   = regexp.MustCompile(`"([^"]+)"\s*:\s*"([^"]*)"`)
	contextNamePattern  = regexp.MustCompile(`(?i)\b(?:name|owner|caller|contact|profile)\s*(?:is|:|-)?\s*([A-Z][A-Za-z'.-]+(?:\s+[A-Z][A-Za-z'.-]+){1,3})\b`)
	locationPattern     = regexp.MustCompile(`(?i)\b(?:location|city|region)\s*(?:is|:|-)?\s*([A-Z][A-Za-z'.-]+(?:[\s,]+[A-Z][A-Za-z'.-]+){0,2})\b`)
	capitalNamePattern  = regexp.MustCompile(`\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b`)
	emailPattern        = regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`)
	usernamePattern     = regexp.MustCompile(`(?i)(?:^|[\s(/])@([A-Z0-9_][A-Z0-9_.]{2,29})\b`)
	googleSegmentRegexp = regexp.MustCompile(`(?is)<h3[^>]*>(.*?)</h3>|<div[^>]+class="[^"]*(?:VwiC3b|IsZvec|BNeawe|aCOpRe)[^"]*"[^>]*>(.*?)</div>|<span[^>]+class="[^"]*(?:st|aCOpRe)[^"]*"[^>]*>(.*?)</span>`)
)

func htmlText(body []byte) string {
	text := scriptPattern.ReplaceAllString(string(body), " ")
	text = stylePattern.ReplaceAllString(text, " ")
	text = htmlTagPattern.ReplaceAllString(text, " ")
	return cleanText(html.UnescapeString(text))
}

func firstJSONValue(body []byte, keys ...string) string {
	keySet := map[string]bool{}
	for _, key := range keys {
		keySet[strings.ToLower(key)] = true
	}
	for _, match := range jsonStringPattern.FindAllStringSubmatch(string(body), -1) {
		if len(match) == 3 && keySet[strings.ToLower(match[1])] {
			return html.UnescapeString(match[2])
		}
	}
	return ""
}

func extractNameFromTitle(body []byte) string {
	match := titlePattern.FindSubmatch(body)
	if len(match) < 2 {
		return ""
	}
	title := cleanText(htmlTagPattern.ReplaceAllString(html.UnescapeString(string(match[1])), " "))
	title = strings.Split(title, "|")[0]
	title = strings.Split(title, "-")[0]
	return cleanName(title)
}

func extractNameWithContext(text string) string {
	match := contextNamePattern.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return cleanName(match[1])
}

func extractLocationWithContext(text string) string {
	match := locationPattern.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return cleanText(match[1])
}

func inferCapitalizedName(text string) string {
	for _, match := range capitalNamePattern.FindAllStringSubmatch(text, -1) {
		if len(match) > 1 {
			if name := cleanName(match[1]); name != "" {
				return name
			}
		}
	}
	return ""
}

func googleSegments(body []byte) []string {
	matches := googleSegmentRegexp.FindAllSubmatch(body, -1)
	segments := make([]string, 0, maxGoogleHits*2)
	seen := map[string]bool{}
	for _, match := range matches {
		for i := 1; i < len(match); i++ {
			if len(match[i]) == 0 {
				continue
			}
			text := cleanText(htmlTagPattern.ReplaceAllString(html.UnescapeString(string(match[i])), " "))
			if text == "" || seen[text] {
				continue
			}
			seen[text] = true
			segments = append(segments, text)
			if len(segments) >= maxGoogleHits*2 {
				return segments
			}
		}
	}
	if len(segments) == 0 {
		text := htmlText(body)
		if text != "" {
			segments = append(segments, text)
		}
	}
	return segments
}

func mentionsNumber(text string, number *core.PhoneNumber, digits string) bool {
	if strings.Contains(text, e164(number)) {
		return true
	}
	textDigits := onlyDigits(text)
	return digits != "" && strings.Contains(textDigits, digits)
}

func extractEmails(text string) []string {
	return emailPattern.FindAllString(text, -1)
}

func extractUsernames(text string) []string {
	matches := usernamePattern.FindAllStringSubmatch(text, -1)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			out = append(out, match[1])
		}
	}
	return out
}

func loadOpenCNAMSID() string {
	if value := strings.TrimSpace(os.Getenv(openCNAMKey)); value != "" {
		return value
	}
	store, err := config.NewDefaultStore()
	if err != nil {
		return ""
	}
	cfg, err := store.Load()
	if err != nil {
		return ""
	}
	for _, key := range []string{openCNAMKey, "opencnam_sid", "opencnam"} {
		if value := strings.TrimSpace(cfg.APIKeys[key]); value != "" {
			return value
		}
	}
	return ""
}

func sourceNames(sources []Source) []string {
	names := make([]string, 0, len(sources))
	for _, source := range sources {
		names = append(names, source.Name())
	}
	return names
}

func numberCountryAlpha2(number *core.PhoneNumber) string {
	if number == nil {
		return ""
	}
	return strings.TrimSpace(number.CountryAlpha2)
}

func e164(number *core.PhoneNumber) string {
	if number == nil {
		return ""
	}
	return firstNonEmpty(number.E164, number.RawInput, number.NationalNumber)
}

func rawLocal(number *core.PhoneNumber) string {
	if number == nil {
		return ""
	}
	return firstNonEmpty(number.NationalNumber, onlyDigits(number.RawInput))
}

func nationalNumber(number *core.PhoneNumber) string {
	if number == nil {
		return ""
	}
	return firstNonEmpty(number.NationalNumber, strings.TrimPrefix(e164(number), "+"))
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

func cleanText(value string) string {
	value = strings.TrimSpace(value)
	return strings.Join(strings.Fields(value), " ")
}

func cleanName(value string) string {
	value = cleanText(value)
	value = strings.Trim(value, `"'[]()<>`)
	if value == "" {
		return ""
	}
	lower := strings.ToLower(value)
	blocked := []string{"truecaller", "google", "search", "unknown", "login", "log in", "phone number", "reverse lookup"}
	for _, word := range blocked {
		if lower == word || strings.Contains(lower, " "+word+" ") {
			return ""
		}
	}
	if len([]rune(value)) > 80 {
		return ""
	}
	return value
}

func compactRaw(value string) string {
	value = cleanText(value)
	if len(value) <= 220 {
		return value
	}
	return strings.TrimSpace(value[:220])
}

func normalizeName(value string) string {
	value = strings.ToLower(cleanName(value))
	value = strings.ReplaceAll(value, ".", "")
	return value
}

func normalizeEmailList(values []string) []string {
	seen := map[string]string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		seen[strings.ToLower(value)] = value
	}
	return sortedMapValues(seen)
}

func normalizeUsernameList(values []string) []string {
	seen := map[string]string{}
	for _, value := range values {
		value = strings.Trim(strings.TrimSpace(value), "@")
		if value == "" {
			continue
		}
		seen[strings.ToLower(value)] = value
	}
	return sortedMapValues(seen)
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

func nonEmpty(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
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

func confidenceRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
