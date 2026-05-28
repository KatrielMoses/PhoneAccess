package search

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/config"
	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

const moduleName = "search"

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Module struct {
	httpClient HTTPClient
	now        func() time.Time
}

type Option func(*Module)

type SearchHit struct {
	Title         string `json:"title"`
	Snippet       string `json:"snippet"`
	URL           string `json:"url"`
	Source        string `json:"source"`
	QueryCategory string `json:"query_category"`
	RetrievedAt   string `json:"retrieved_at"`
}

type SearchResult struct {
	Hits           []SearchHit       `json:"hits"`
	Emails         []string          `json:"emails,omitempty"`
	Names          []string          `json:"names,omitempty"`
	SocialLinks    []string          `json:"social_links,omitempty"`
	SourceStatuses map[string]string `json:"source_statuses"`
	Skipped        bool              `json:"skipped,omitempty"`
	Note           string            `json:"note,omitempty"`
}

type querySpec struct {
	category string
	clause   string
}

func New(opts ...Option) *Module {
	m := &Module{
		httpClient: core.NewHTTPClient(core.DefaultHTTPTimeout),
		now:        func() time.Time { return time.Now().UTC() },
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

func (m *Module) Name() string {
	return moduleName
}

func (m *Module) Description() string {
	return "Targeted search execution across Google CSE and Bing for phone-number intelligence."
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
	return &core.ModuleResult{
		ModuleName: m.Name(),
		Status:     core.ModuleStatusSkipped,
		Findings:   findings(SearchResult{Skipped: true, Note: "passive mode disables search execution", SourceStatuses: map[string]string{}}),
		Data:       SearchResult{Skipped: true, Note: "passive mode disables search execution", SourceStatuses: map[string]string{}},
		Evidence:   []string{"Passive mode enabled; search module made no network requests."},
	}, nil
}

func (m *Module) Run(ctx context.Context, number *core.PhoneNumber) (*core.ModuleResult, error) {
	queries := buildQueries(number)
	result := SearchResult{
		Hits:           []SearchHit{},
		SourceStatuses: map[string]string{},
	}

	googleKey, googleCX := loadGoogleKeys()
	bingKey := loadBingKey()

	if googleKey == "" || googleCX == "" {
		result.SourceStatuses["google"] = "skipped: missing GOOGLE_CSE_API_KEY or GOOGLE_CSE_CX"
	}
	if bingKey == "" {
		result.SourceStatuses["bing"] = "skipped: missing BING_SEARCH_API_KEY"
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	seen := map[string]bool{}
	addHit := func(hit SearchHit) {
		if strings.TrimSpace(hit.URL) == "" {
			return
		}
		key := strings.ToLower(strings.TrimSpace(hit.URL))
		mu.Lock()
		defer mu.Unlock()
		if seen[key] {
			return
		}
		seen[key] = true
		result.Hits = append(result.Hits, hit)
	}
	runSource := func(source string, fetch func(context.Context, querySpec) ([]SearchHit, error)) {
		defer wg.Done()
		for _, spec := range queries {
			hits, err := fetch(ctx, spec)
			mu.Lock()
			if err != nil {
				result.SourceStatuses[source+"."+spec.category] = err.Error()
				mu.Unlock()
				continue
			}
			if len(hits) == 0 {
				result.SourceStatuses[source+"."+spec.category] = "no results"
			} else {
				result.SourceStatuses[source+"."+spec.category] = "hit"
			}
			mu.Unlock()
			for _, hit := range hits {
				addHit(hit)
			}
		}
	}

	if googleKey != "" && googleCX != "" {
		wg.Add(1)
		go runSource("google", func(ctx context.Context, spec querySpec) ([]SearchHit, error) {
			return m.googleSearch(ctx, googleKey, googleCX, spec)
		})
	}
	if bingKey != "" {
		wg.Add(1)
		go runSource("bing", func(ctx context.Context, spec querySpec) ([]SearchHit, error) {
			return m.bingSearch(ctx, bingKey, spec)
		})
	}
	wg.Wait()

	sort.SliceStable(result.Hits, func(i, j int) bool {
		if result.Hits[i].Source == result.Hits[j].Source {
			if result.Hits[i].QueryCategory == result.Hits[j].QueryCategory {
				return result.Hits[i].Title < result.Hits[j].Title
			}
			return result.Hits[i].QueryCategory < result.Hits[j].QueryCategory
		}
		return result.Hits[i].Source < result.Hits[j].Source
	})

	collectSearchSignals(&result)

	if len(result.Hits) == 0 {
		if googleKey == "" && bingKey == "" {
			result.Skipped = true
			result.Note = "no supported search API keys configured"
			return &core.ModuleResult{
				ModuleName: m.Name(),
				Status:     core.ModuleStatusSkipped,
				Findings:   findings(result),
				Data:       result,
				Evidence:   []string{"Search execution skipped because no API keys were configured."},
			}, nil
		}
	}

	evidence := []string{}
	for key, status := range result.SourceStatuses {
		evidence = append(evidence, key+": "+status)
	}
	sort.Strings(evidence)
	return &core.ModuleResult{
		ModuleName: m.Name(),
		Status:     core.ModuleStatusSuccess,
		Findings:   findings(result),
		Data:       result,
		Evidence:   evidence,
	}, nil
}

func (m *Module) googleSearch(ctx context.Context, apiKey, cx string, spec querySpec) ([]SearchHit, error) {
	return GoogleCSESearch(ctx, m.httpClient, apiKey, cx, spec.clause, spec.category, m.now())
}

func GoogleCSESearch(ctx context.Context, client HTTPClient, apiKey, cx, query, category string, now time.Time) ([]SearchHit, error) {
	endpoint, _ := url.Parse("https://www.googleapis.com/customsearch/v1")
	params := endpoint.Query()
	params.Set("q", buildQuery(query))
	params.Set("key", apiKey)
	params.Set("cx", cx)
	params.Set("num", "10")
	endpoint.RawQuery = params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	core.SetDefaultHeaders(req)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("google cse http status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var decoded struct {
		Items []struct {
			Title        string `json:"title"`
			Snippet      string `json:"snippet"`
			Link         string `json:"link"`
			FormattedURL string `json:"formattedUrl"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, err
	}
	return toHits("google", category, decoded.Items, now), nil
}

func (m *Module) bingSearch(ctx context.Context, apiKey string, spec querySpec) ([]SearchHit, error) {
	endpoint, _ := url.Parse("https://api.bing.microsoft.com/v7.0/search")
	query := endpoint.Query()
	query.Set("q", buildQuery(spec.clause))
	query.Set("count", "10")
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	core.SetDefaultHeaders(req)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Ocp-Apim-Subscription-Key", apiKey)
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("bing search http status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var decoded struct {
		WebPages struct {
			Value []struct {
				Name            string `json:"name"`
				Snippet         string `json:"snippet"`
				URL             string `json:"url"`
				DateLastCrawled string `json:"dateLastCrawled"`
			} `json:"value"`
		} `json:"webPages"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, err
	}
	return toHits("bing", spec.category, decoded.WebPages.Value, m.now()), nil
}

func toHits[T any](source, category string, items []T, now time.Time) []SearchHit {
	hits := make([]SearchHit, 0, len(items))
	for _, item := range items {
		raw, _ := json.Marshal(item)
		var generic map[string]any
		_ = json.Unmarshal(raw, &generic)
		title, _ := generic["title"].(string)
		if title == "" {
			title, _ = generic["name"].(string)
		}
		snippet, _ := generic["snippet"].(string)
		link, _ := generic["link"].(string)
		if link == "" {
			link, _ = generic["url"].(string)
		}
		if link == "" {
			link, _ = generic["formattedUrl"].(string)
		}
		if strings.TrimSpace(link) == "" {
			continue
		}
		hits = append(hits, SearchHit{
			Title:         cleanText(title),
			Snippet:       cleanText(snippet),
			URL:           strings.TrimSpace(link),
			Source:        source,
			QueryCategory: category,
			RetrievedAt:   now.UTC().Format(time.RFC3339),
		})
	}
	return hits
}

func buildQueries(number *core.PhoneNumber) []querySpec {
	return []querySpec{
		{category: "paste_sites", clause: core.SearchQueryPhrase(number) + " site:pastebin.com"},
		{category: "paste_sites", clause: core.SearchQueryPhrase(number) + " site:ghostbin.co"},
		{category: "documents", clause: core.SearchQueryPhrase(number) + " (ext:pdf OR ext:doc OR ext:csv OR ext:xls)"},
		{category: "classifieds", clause: core.SearchQueryPhrase(number) + " site:craigslist.org"},
		{category: "classifieds", clause: core.SearchQueryPhrase(number) + " site:reddit.com"},
		{category: "reputation", clause: core.SearchQueryPhrase(number) + " site:bbb.org"},
		{category: "reputation", clause: core.SearchQueryPhrase(number) + " site:yelp.com"},
		{category: "court_records", clause: core.SearchQueryPhrase(number) + " site:courtlistener.com"},
		{category: "court_records", clause: core.SearchQueryPhrase(number) + " filetype:pdf site:*.gov"},
	}
}

func buildQuery(clause string) string {
	return strings.TrimSpace(clause)
}

func collectSearchSignals(result *SearchResult) {
	emailSet := map[string]string{}
	nameSet := map[string]string{}
	urlSet := map[string]string{}
	for _, hit := range result.Hits {
		text := strings.TrimSpace(hit.Title + " " + hit.Snippet)
		for _, email := range emailPattern.FindAllString(text, -1) {
			emailSet[strings.ToLower(email)] = email
		}
		for _, name := range namePattern.FindAllString(text, -1) {
			nameSet[strings.ToLower(name)] = name
		}
		for _, matched := range urlPattern.FindAllString(text, -1) {
			urlSet[strings.ToLower(matched)] = matched
		}
	}
	result.Emails = sortedMapValues(emailSet)
	result.Names = sortedMapValues(nameSet)
	result.SocialLinks = sortedMapValues(urlSet)
}

func findings(result SearchResult) map[string]string {
	return map[string]string{
		"hits":            formatHits(result.Hits),
		"emails":          strings.Join(result.Emails, ", "),
		"names":           strings.Join(result.Names, ", "),
		"social_links":    strings.Join(result.SocialLinks, ", "),
		"source_statuses": joinStatuses(result.SourceStatuses),
		"skipped":         strconv.FormatBool(result.Skipped),
		"note":            result.Note,
	}
}

func formatHits(hits []SearchHit) string {
	lines := make([]string, 0, len(hits))
	for _, hit := range hits {
		line := fmt.Sprintf("[%s] %s", hit.Source, hit.Title)
		if hit.QueryCategory != "" {
			line += " {" + hit.QueryCategory + "}"
		}
		if hit.Snippet != "" {
			line += ": " + hit.Snippet
		}
		if hit.URL != "" {
			line += " <" + hit.URL + ">"
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func loadGoogleKeys() (string, string) {
	apiKey := strings.TrimSpace(os.Getenv("GOOGLE_CSE_API_KEY"))
	cx := strings.TrimSpace(os.Getenv("GOOGLE_CSE_CX"))
	if apiKey != "" && cx != "" {
		return apiKey, cx
	}
	store, err := config.NewDefaultStore()
	if err != nil {
		return apiKey, cx
	}
	cfg, err := store.Load()
	if err != nil {
		return apiKey, cx
	}
	if apiKey == "" {
		apiKey = strings.TrimSpace(cfg.APIKeys["GOOGLE_CSE_API_KEY"])
	}
	if cx == "" {
		cx = strings.TrimSpace(cfg.APIKeys["GOOGLE_CSE_CX"])
	}
	return apiKey, cx
}

func loadBingKey() string {
	key := strings.TrimSpace(os.Getenv("BING_SEARCH_API_KEY"))
	if key != "" {
		return key
	}
	store, err := config.NewDefaultStore()
	if err != nil {
		return ""
	}
	cfg, err := store.Load()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cfg.APIKeys["BING_SEARCH_API_KEY"])
}

var (
	emailPattern = regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`)
	namePattern  = regexp.MustCompile(`\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b`)
	urlPattern   = regexp.MustCompile(`(?i)\bhttps?://[^\s<>"')]+`)
)

func cleanText(value string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
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

func joinStatuses(statuses map[string]string) string {
	keys := make([]string, 0, len(statuses))
	for key := range statuses {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+statuses[key])
	}
	return strings.Join(parts, "; ")
}
