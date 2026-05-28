package paste

import (
	"context"
	"encoding/base64"
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

const moduleName = "paste"

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Module struct {
	httpClient    HTTPClient
	now           func() time.Time
	githubLimiter *core.RateLimiter
	redditLimiter *core.RateLimiter
}

type Option func(*Module)

type PsbdmpHit struct {
	PasteID string   `json:"paste_id"`
	Date    string   `json:"date"`
	Preview string   `json:"preview"`
	Emails  []string `json:"emails,omitempty"`
	Names   []string `json:"names,omitempty"`
	URL     string   `json:"url,omitempty"`
}

type GitHubCodeHit struct {
	TotalCount int    `json:"total_count"`
	Repo       string `json:"repo"`
	Path       string `json:"path"`
	HTMLURL    string `json:"html_url"`
	CreatedAt  string `json:"created_at,omitempty"`
}

type RedditPost struct {
	Title      string `json:"title"`
	Subreddit  string `json:"subreddit"`
	CreatedUTC int64  `json:"created_utc"`
	URL        string `json:"url"`
	Score      int    `json:"score"`
}

type IntelXHit struct {
	UUID       string `json:"uuid,omitempty"`
	SourceName string `json:"source_name"`
	Type       string `json:"type"`
	IndexDate  string `json:"index_date"`
}

type DeHashedEntry struct {
	DatabaseName string `json:"database_name"`
	Email        string `json:"email,omitempty"`
	Username     string `json:"username,omitempty"`
	Name         string `json:"name,omitempty"`
	Date         string `json:"date,omitempty"`
}

type PasteResult struct {
	PsbdmpHits     []PsbdmpHit       `json:"psbdmp_hits,omitempty"`
	GitHubHits     []GitHubCodeHit   `json:"github_hits,omitempty"`
	RedditHits     []RedditPost      `json:"reddit_hits,omitempty"`
	IntelXHits     []IntelXHit       `json:"intelx_hits,omitempty"`
	DeHashedHits   []DeHashedEntry   `json:"dehashed_hits,omitempty"`
	Emails         []string          `json:"emails,omitempty"`
	Names          []string          `json:"names,omitempty"`
	SocialLinks    []string          `json:"social_links,omitempty"`
	SourceStatuses map[string]string `json:"source_statuses"`
	Skipped        bool              `json:"skipped,omitempty"`
	Note           string            `json:"note,omitempty"`
}

func New(opts ...Option) *Module {
	m := &Module{
		httpClient:    core.NewHTTPClient(core.DefaultHTTPTimeout),
		now:           func() time.Time { return time.Now().UTC() },
		githubLimiter: core.NewRateLimiter(6 * time.Second),
		redditLimiter: core.NewRateLimiter(time.Minute),
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
	return "Paste, leak, and code-search intelligence for phone numbers."
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
	result := PasteResult{
		SourceStatuses: map[string]string{},
		Skipped:        true,
		Note:           "passive mode disables paste and leak monitoring requests",
	}
	return &core.ModuleResult{
		ModuleName: m.Name(),
		Status:     core.ModuleStatusSkipped,
		Findings:   findings(result),
		Data:       result,
		Evidence:   []string{"Passive mode enabled; paste module made no network requests."},
	}, nil
}

func (m *Module) Run(ctx context.Context, number *core.PhoneNumber) (*core.ModuleResult, error) {
	result := PasteResult{SourceStatuses: map[string]string{}}
	var mu sync.Mutex

	collect := func(key string, fn func() error) {
		if err := fn(); err != nil {
			mu.Lock()
			result.SourceStatuses[key] = err.Error()
			mu.Unlock()
		}
	}

	collect("psbdmp", func() error {
		hits, err := m.searchPsbdmp(ctx, number)
		if err != nil {
			return err
		}
		result.PsbdmpHits = hits
		if len(hits) == 0 {
			result.SourceStatuses["psbdmp"] = "no results"
		} else {
			result.SourceStatuses["psbdmp"] = "hit"
		}
		return nil
	})

	collect("github", func() error {
		token := loadGitHubToken()
		if m.githubLimiter != nil {
			if err := m.githubLimiter.Wait(ctx, "github"); err != nil {
				return err
			}
		}
		hits, err := m.searchGitHub(ctx, token, number)
		if err != nil {
			return err
		}
		result.GitHubHits = hits
		if len(hits) == 0 {
			result.SourceStatuses["github"] = "no results"
		} else {
			result.SourceStatuses["github"] = "hit"
		}
		return nil
	})

	collect("reddit", func() error {
		if m.redditLimiter != nil {
			if err := m.redditLimiter.Wait(ctx, "reddit"); err != nil {
				return err
			}
		}
		hits, err := m.searchReddit(ctx, number)
		if err != nil {
			return err
		}
		result.RedditHits = hits
		if len(hits) == 0 {
			result.SourceStatuses["reddit"] = "no results"
		} else {
			result.SourceStatuses["reddit"] = "hit"
		}
		return nil
	})

	collect("intelx", func() error {
		key := loadIntelXKey()
		if key == "" {
			return fmt.Errorf("skipped: missing INTELX_API_KEY")
		}
		hits, err := m.searchIntelX(ctx, key, number)
		if err != nil {
			return err
		}
		result.IntelXHits = hits
		if len(hits) == 0 {
			result.SourceStatuses["intelx"] = "no results"
		} else {
			result.SourceStatuses["intelx"] = "hit"
		}
		return nil
	})

	collect("dehashed", func() error {
		email, apiKey := loadDeHashedCreds()
		if email == "" || apiKey == "" {
			return fmt.Errorf("skipped: missing DEHASHED_EMAIL or DEHASHED_API_KEY")
		}
		hits, err := m.searchDeHashed(ctx, email, apiKey, number)
		if err != nil {
			return err
		}
		result.DeHashedHits = hits
		if len(hits) == 0 {
			result.SourceStatuses["dehashed"] = "no results"
		} else {
			result.SourceStatuses["dehashed"] = "hit"
		}
		return nil
	})

	collectPasteSignals(&result)
	sort.SliceStable(result.PsbdmpHits, func(i, j int) bool { return result.PsbdmpHits[i].Date < result.PsbdmpHits[j].Date })
	sort.SliceStable(result.GitHubHits, func(i, j int) bool { return result.GitHubHits[i].CreatedAt < result.GitHubHits[j].CreatedAt })
	sort.SliceStable(result.RedditHits, func(i, j int) bool { return result.RedditHits[i].CreatedUTC < result.RedditHits[j].CreatedUTC })
	sort.SliceStable(result.IntelXHits, func(i, j int) bool { return result.IntelXHits[i].IndexDate < result.IntelXHits[j].IndexDate })
	sort.SliceStable(result.DeHashedHits, func(i, j int) bool { return result.DeHashedHits[i].Date < result.DeHashedHits[j].Date })

	allSkipped := true
	for _, status := range result.SourceStatuses {
		if !strings.HasPrefix(status, "skipped:") {
			allSkipped = false
			break
		}
	}
	if allSkipped && len(result.SourceStatuses) > 0 {
		result.Skipped = true
		result.Note = "no configured paste/intel sources were available"
		return &core.ModuleResult{
			ModuleName: m.Name(),
			Status:     core.ModuleStatusSkipped,
			Findings:   findings(result),
			Data:       result,
			Evidence:   []string{"Paste module skipped because no configured sources were available."},
		}, nil
	}

	return &core.ModuleResult{
		ModuleName: m.Name(),
		Status:     core.ModuleStatusSuccess,
		Findings:   findings(result),
		Data:       result,
		Evidence:   evidence(result.SourceStatuses),
	}, nil
}

func (m *Module) get(ctx context.Context, endpoint string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	core.SetDefaultHeaders(req)
	req.Header.Set("Accept", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func (m *Module) searchPsbdmp(ctx context.Context, number *core.PhoneNumber) ([]PsbdmpHit, error) {
	var hits []PsbdmpHit
	for _, variant := range core.SearchVariantsFor(number) {
		if strings.TrimSpace(variant) == "" {
			continue
		}
		endpoint := fmt.Sprintf("https://psbdmp.ws/api/search/%s", url.PathEscape(variant))
		body, err := m.get(ctx, endpoint, nil)
		if err != nil {
			return nil, err
		}
		found, err := parsePsbdmpSearch(body)
		if err != nil {
			return nil, err
		}
		for _, item := range found {
			preview, err := m.get(ctx, fmt.Sprintf("https://psbdmp.ws/api/get/%s", url.PathEscape(item.PasteID)), nil)
			if err != nil {
				return nil, err
			}
			content, err := parsePsbdmpPreview(preview)
			if err != nil {
				return nil, err
			}
			text := cleanText(content)
			item.Preview = firstN(text, 500)
			item.Emails = uniqueMatches(emailPattern.FindAllString(text, -1))
			item.Names = uniqueMatches(namePattern.FindAllString(text, -1))
			item.URL = "https://psbdmp.ws/p/" + item.PasteID
			hits = append(hits, item)
		}
	}
	return dedupePsbdmp(hits), nil
}

func (m *Module) searchGitHub(ctx context.Context, token string, number *core.PhoneNumber) ([]GitHubCodeHit, error) {
	q := core.SearchQueryPhrase(number)
	endpoint, _ := url.Parse("https://api.github.com/search/code")
	params := endpoint.Query()
	params.Set("q", q)
	params.Set("per_page", "10")
	endpoint.RawQuery = params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	core.SetDefaultHeaders(req)
	req.Header.Set("Accept", "application/vnd.github+json")
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("github search http status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var decoded struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			Repository struct {
				FullName  string `json:"full_name"`
				CreatedAt string `json:"created_at"`
			} `json:"repository"`
			Path    string `json:"path"`
			HTMLURL string `json:"html_url"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, err
	}
	hits := make([]GitHubCodeHit, 0, len(decoded.Items))
	for _, item := range decoded.Items {
		hits = append(hits, GitHubCodeHit{
			TotalCount: decoded.TotalCount,
			Repo:       item.Repository.FullName,
			Path:       item.Path,
			HTMLURL:    item.HTMLURL,
			CreatedAt:  item.Repository.CreatedAt,
		})
	}
	return hits, nil
}

func (m *Module) searchReddit(ctx context.Context, number *core.PhoneNumber) ([]RedditPost, error) {
	endpoint, _ := url.Parse("https://www.reddit.com/search.json")
	params := endpoint.Query()
	params.Set("q", core.SearchQueryPhrase(number))
	params.Set("type", "link")
	params.Set("limit", "25")
	endpoint.RawQuery = params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	core.SetDefaultHeaders(req)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "PhoneAccess/0.1.0")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("reddit search http status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var decoded struct {
		Data struct {
			Children []struct {
				Data struct {
					Title      string  `json:"title"`
					Subreddit  string  `json:"subreddit"`
					CreatedUTC float64 `json:"created_utc"`
					URL        string  `json:"url"`
					Score      int     `json:"score"`
					SelfText   string  `json:"selftext"`
				} `json:"data"`
			} `json:"children"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, err
	}
	hits := []RedditPost{}
	for _, child := range decoded.Data.Children {
		item := child.Data
		text := item.Title + " " + item.SelfText
		if !mentionsAnyVariant(text, core.SearchVariantsFor(number)) {
			continue
		}
		hits = append(hits, RedditPost{
			Title:      cleanText(item.Title),
			Subreddit:  item.Subreddit,
			CreatedUTC: int64(item.CreatedUTC),
			URL:        item.URL,
			Score:      item.Score,
		})
	}
	return hits, nil
}

func (m *Module) searchIntelX(ctx context.Context, key string, number *core.PhoneNumber) ([]IntelXHit, error) {
	endpoint := "https://2.intelx.io/phonebook/search"
	reqBody := map[string]any{"term": core.SearchVariantsFor(number)[0], "maxresults": 10, "sort": 4, "media": 0}
	body, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	core.SetDefaultHeaders(req)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-key", key)
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("intelx search http status %d", resp.StatusCode)
	}
	searchBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var start struct {
		ID   string `json:"id"`
		UUID string `json:"uuid"`
	}
	if err := json.Unmarshal(searchBody, &start); err != nil {
		return nil, err
	}
	pollID := firstNonEmpty(start.ID, start.UUID)
	if pollID == "" {
		return nil, nil
	}
	pollURL := fmt.Sprintf("https://2.intelx.io/phonebook/search/result?id=%s&limit=10", url.QueryEscape(pollID))
	pollReq, err := http.NewRequestWithContext(ctx, http.MethodGet, pollURL, nil)
	if err != nil {
		return nil, err
	}
	core.SetDefaultHeaders(pollReq)
	pollReq.Header.Set("Accept", "application/json")
	pollReq.Header.Set("x-key", key)
	pollResp, err := m.httpClient.Do(pollReq)
	if err != nil {
		return nil, err
	}
	defer pollResp.Body.Close()
	if pollResp.StatusCode < 200 || pollResp.StatusCode >= 300 {
		return nil, fmt.Errorf("intelx poll http status %d", pollResp.StatusCode)
	}
	pollBody, err := io.ReadAll(pollResp.Body)
	if err != nil {
		return nil, err
	}
	var decoded struct {
		Results []struct {
			SourceName string `json:"source_name"`
			Type       string `json:"type"`
			IndexDate  string `json:"indexdate"`
		} `json:"results"`
	}
	if err := json.Unmarshal(pollBody, &decoded); err != nil {
		return nil, err
	}
	hits := make([]IntelXHit, 0, len(decoded.Results))
	for _, item := range decoded.Results {
		hits = append(hits, IntelXHit{SourceName: item.SourceName, Type: item.Type, IndexDate: item.IndexDate, UUID: pollID})
	}
	return hits, nil
}

func (m *Module) searchDeHashed(ctx context.Context, email, apiKey string, number *core.PhoneNumber) ([]DeHashedEntry, error) {
	endpoint, _ := url.Parse("https://api.dehashed.com/search")
	params := endpoint.Query()
	params.Set("query", "phone:"+firstNonEmpty(number.E164, number.NationalNumber))
	params.Set("size", "10")
	endpoint.RawQuery = params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	core.SetDefaultHeaders(req)
	req.Header.Set("Accept", "application/json")
	auth := base64.StdEncoding.EncodeToString([]byte(email + ":" + apiKey))
	req.Header.Set("Authorization", "Basic "+auth)
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("dehashed http status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var decoded struct {
		Entries []struct {
			DatabaseName string `json:"database_name"`
			Email        string `json:"email"`
			Username     string `json:"username"`
			Name         string `json:"name"`
			Date         string `json:"date"`
		} `json:"entries"`
		Results []struct {
			DatabaseName string `json:"database_name"`
			Email        string `json:"email"`
			Username     string `json:"username"`
			Name         string `json:"name"`
			Date         string `json:"date"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, err
	}
	var hits []DeHashedEntry
	for _, item := range append(decoded.Entries, decoded.Results...) {
		hits = append(hits, DeHashedEntry{
			DatabaseName: item.DatabaseName,
			Email:        item.Email,
			Username:     item.Username,
			Name:         item.Name,
			Date:         item.Date,
		})
	}
	return hits, nil
}

func parsePsbdmpSearch(body []byte) ([]PsbdmpHit, error) {
	if len(body) == 0 {
		return nil, nil
	}
	var hits []PsbdmpHit
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	switch v := raw.(type) {
	case []any:
		for _, item := range v {
			if hit := psbdmpHitFromAny(item); hit.PasteID != "" {
				hits = append(hits, hit)
			}
		}
	case map[string]any:
		for _, key := range []string{"data", "result", "items", "hits"} {
			if arr, ok := v[key].([]any); ok {
				for _, item := range arr {
					if hit := psbdmpHitFromAny(item); hit.PasteID != "" {
						hits = append(hits, hit)
					}
				}
			}
		}
	}
	return hits, nil
}

func parsePsbdmpPreview(body []byte) (string, error) {
	if len(body) == 0 {
		return "", nil
	}
	var raw any
	if err := json.Unmarshal(body, &raw); err == nil {
		switch v := raw.(type) {
		case map[string]any:
			for _, key := range []string{"content", "data", "text", "body", "preview"} {
				if text, ok := v[key].(string); ok {
					return text, nil
				}
			}
		case string:
			return v, nil
		}
	}
	return string(body), nil
}

func psbdmpHitFromAny(value any) PsbdmpHit {
	raw, _ := json.Marshal(value)
	var generic map[string]any
	_ = json.Unmarshal(raw, &generic)
	hit := PsbdmpHit{}
	hit.PasteID = firstNonEmpty(stringField(generic, "id"), stringField(generic, "paste_id"), stringField(generic, "uuid"))
	hit.Date = firstNonEmpty(stringField(generic, "date"), stringField(generic, "created_at"), stringField(generic, "timestamp"))
	return hit
}

func dedupePsbdmp(hits []PsbdmpHit) []PsbdmpHit {
	seen := map[string]bool{}
	out := make([]PsbdmpHit, 0, len(hits))
	for _, hit := range hits {
		if hit.PasteID == "" || seen[strings.ToLower(hit.PasteID)] {
			continue
		}
		seen[strings.ToLower(hit.PasteID)] = true
		out = append(out, hit)
	}
	return out
}

func collectPasteSignals(result *PasteResult) {
	emails := map[string]string{}
	names := map[string]string{}
	urls := map[string]string{}
	addText := func(text string) {
		for _, email := range emailPattern.FindAllString(text, -1) {
			emails[strings.ToLower(email)] = email
		}
		for _, name := range namePattern.FindAllString(text, -1) {
			names[strings.ToLower(name)] = name
		}
		for _, matched := range urlPattern.FindAllString(text, -1) {
			urls[strings.ToLower(matched)] = matched
		}
	}
	for _, hit := range result.PsbdmpHits {
		addText(hit.Preview)
		for _, email := range hit.Emails {
			emails[strings.ToLower(email)] = email
		}
		for _, name := range hit.Names {
			names[strings.ToLower(name)] = name
		}
	}
	for _, hit := range result.GitHubHits {
		addText(hit.Repo + " " + hit.Path + " " + hit.HTMLURL)
	}
	for _, hit := range result.RedditHits {
		addText(hit.Title + " " + hit.URL + " " + hit.Subreddit)
	}
	for _, hit := range result.DeHashedHits {
		addText(hit.Email + " " + hit.Username + " " + hit.Name + " " + hit.DatabaseName)
		if hit.Email != "" {
			emails[strings.ToLower(hit.Email)] = hit.Email
		}
		if hit.Name != "" {
			names[strings.ToLower(hit.Name)] = hit.Name
		}
	}
	result.Emails = sortedMapValues(emails)
	result.Names = sortedMapValues(names)
	result.SocialLinks = sortedMapValues(urls)
}

func findings(result PasteResult) map[string]string {
	return map[string]string{
		"psbdmp_hits":     formatPsbdmp(result.PsbdmpHits),
		"github_hits":     formatGitHub(result.GitHubHits),
		"reddit_hits":     formatReddit(result.RedditHits),
		"intelx_hits":     formatIntelX(result.IntelXHits),
		"dehashed_hits":   formatDeHashed(result.DeHashedHits),
		"emails":          strings.Join(result.Emails, ", "),
		"names":           strings.Join(result.Names, ", "),
		"social_links":    strings.Join(result.SocialLinks, ", "),
		"source_statuses": joinStatuses(result.SourceStatuses),
		"skipped":         strconv.FormatBool(result.Skipped),
		"note":            result.Note,
	}
}

func formatPsbdmp(hits []PsbdmpHit) string {
	lines := make([]string, 0, len(hits))
	for _, hit := range hits {
		line := hit.PasteID
		if hit.Date != "" {
			line += " " + hit.Date
		}
		if hit.Preview != "" {
			line += ": " + hit.Preview
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func formatGitHub(hits []GitHubCodeHit) string {
	lines := make([]string, 0, len(hits))
	for _, hit := range hits {
		line := fmt.Sprintf("%s %s", hit.Repo, hit.Path)
		if hit.CreatedAt != "" {
			line += " " + hit.CreatedAt
		}
		if hit.HTMLURL != "" {
			line += " <" + hit.HTMLURL + ">"
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func formatReddit(hits []RedditPost) string {
	lines := make([]string, 0, len(hits))
	for _, hit := range hits {
		line := hit.Title
		if hit.Subreddit != "" {
			line += " [" + hit.Subreddit + "]"
		}
		if hit.CreatedUTC > 0 {
			line += " " + strconv.FormatInt(hit.CreatedUTC, 10)
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func formatIntelX(hits []IntelXHit) string {
	lines := make([]string, 0, len(hits))
	for _, hit := range hits {
		line := hit.SourceName
		if hit.Type != "" {
			line += " (" + hit.Type + ")"
		}
		if hit.IndexDate != "" {
			line += " " + hit.IndexDate
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func formatDeHashed(hits []DeHashedEntry) string {
	lines := make([]string, 0, len(hits))
	for _, hit := range hits {
		line := hit.DatabaseName
		if hit.Email != "" {
			line += " " + hit.Email
		}
		if hit.Username != "" {
			line += " @" + hit.Username
		}
		if hit.Name != "" {
			line += " " + hit.Name
		}
		if hit.Date != "" {
			line += " " + hit.Date
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func evidence(statuses map[string]string) []string {
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

func loadGitHubToken() string {
	token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	if token != "" {
		return token
	}
	store, err := config.NewDefaultStore()
	if err != nil {
		return ""
	}
	cfg, err := store.Load()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cfg.APIKeys["GITHUB_TOKEN"])
}

func loadIntelXKey() string {
	key := strings.TrimSpace(os.Getenv("INTELX_API_KEY"))
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
	return strings.TrimSpace(cfg.APIKeys["INTELX_API_KEY"])
}

func loadDeHashedCreds() (string, string) {
	email := strings.TrimSpace(os.Getenv("DEHASHED_EMAIL"))
	key := strings.TrimSpace(os.Getenv("DEHASHED_API_KEY"))
	store, err := config.NewDefaultStore()
	if err == nil {
		cfg, err := store.Load()
		if err == nil {
			if email == "" {
				email = strings.TrimSpace(cfg.APIKeys["DEHASHED_EMAIL"])
			}
			if key == "" {
				key = strings.TrimSpace(cfg.APIKeys["DEHASHED_API_KEY"])
			}
		}
	}
	return email, key
}

func mentionsAnyVariant(text string, variants []string) bool {
	lower := strings.ToLower(text)
	for _, variant := range variants {
		if strings.TrimSpace(variant) != "" && strings.Contains(lower, strings.ToLower(variant)) {
			return true
		}
	}
	return false
}

func uniqueMatches(values []string) []string {
	seen := map[string]string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[strings.ToLower(value)] = value
		}
	}
	return sortedMapValues(seen)
}

func stringField(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	if value, ok := values[key].(string); ok {
		return value
	}
	return ""
}

func firstN(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit]
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
