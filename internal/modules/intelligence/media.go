package intelligence

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

const (
	googleNewsRSSURL = "https://news.google.com/rss/search"
	maxMediaBody     = 2 * 1024 * 1024
)

// adverseKeywords are the financial/legal/criminal terms that indicate risk.
var adverseKeywords = []string{
	"fraud", "scam", "arrest", "convicted", "lawsuit", "sanction",
	"money laundering", "terrorism", "investigation", "charged", "indicted",
}

type rssChannel struct {
	Items []rssItem `xml:"channel>item"`
}

type rssItem struct {
	Title   string    `xml:"title"`
	Link    string    `xml:"link"`
	PubDate string    `xml:"pubDate"`
	Desc    string    `xml:"description"`
	Source  rssSource `xml:"source"`
}

type rssSource struct {
	Name string `xml:",chardata"`
}

var htmlTagPattern = regexp.MustCompile(`<[^>]+>`)

func (m *Module) fetchMedia(ctx context.Context, number *core.PhoneNumber) MediaResult {
	queries := []string{number.E164}
	// Also search the national number without country code if it differs.
	if number.NationalNumber != "" && number.NationalNumber != number.E164 {
		queries = append(queries, number.NationalNumber)
	}

	seen := map[string]bool{}
	var articles []MediaArticle
	kwSeen := map[string]bool{}

	for _, q := range queries {
		if err := m.mediaLimiter.Wait(ctx, "google-news"); err != nil {
			break
		}
		for _, item := range m.fetchNewsRSS(ctx, q) {
			if seen[item.URL] {
				continue
			}
			// OR logic for phone queries: include if any adverse keyword found.
			kws := matchedKeywords(item.Title + " " + item.Snippet)
			if len(kws) == 0 {
				continue
			}
			seen[item.URL] = true
			for _, kw := range kws {
				kwSeen[kw] = true
			}
			articles = append(articles, item)
		}
	}

	sort.SliceStable(articles, func(i, j int) bool {
		return articles[i].PublishedAt.After(articles[j].PublishedAt)
	})

	allKWs := make([]string, 0, len(kwSeen))
	for kw := range kwSeen {
		allKWs = append(allKWs, kw)
	}
	sort.Strings(allKWs)

	sourceSeen := map[string]bool{}
	var sources []string
	for _, a := range articles {
		if a.Source != "" && !sourceSeen[a.Source] {
			sourceSeen[a.Source] = true
			sources = append(sources, a.Source)
		}
	}

	return MediaResult{
		ArticleCount: len(articles),
		Articles:     articles,
		RiskKeywords: allKWs,
		Sources:      sources,
	}
}

func (m *Module) fetchNewsRSS(ctx context.Context, query string) []MediaArticle {
	params := url.Values{}
	params.Set("q", `"`+query+`"`)
	params.Set("hl", "en-US")
	params.Set("gl", "US")
	params.Set("ceid", "US:en")
	reqURL := googleNewsRSSURL + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/rss+xml, application/xml, text/xml")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var feed rssChannel
	if err := xml.NewDecoder(io.LimitReader(resp.Body, maxMediaBody)).Decode(&feed); err != nil {
		return nil
	}

	articles := make([]MediaArticle, 0, len(feed.Items))
	for _, item := range feed.Items {
		a := parseRSSItem(item)
		if a.URL == "" && a.Title == "" {
			continue
		}
		articles = append(articles, a)
	}
	return articles
}

func parseRSSItem(item rssItem) MediaArticle {
	title := strings.TrimSpace(item.Title)
	snippet := strings.TrimSpace(htmlTagPattern.ReplaceAllString(item.Desc, " "))
	snippet = strings.Join(strings.Fields(snippet), " ")
	if len(snippet) > 300 {
		snippet = snippet[:300]
	}

	source := strings.TrimSpace(item.Source.Name)
	if source == "" {
		if idx := strings.LastIndex(title, " - "); idx > 0 {
			source = strings.TrimSpace(title[idx+3:])
			title = strings.TrimSpace(title[:idx])
		}
	}

	return MediaArticle{
		Title:       title,
		URL:         strings.TrimSpace(item.Link),
		Source:      source,
		PublishedAt: parseRSSDate(item.PubDate),
		Snippet:     snippet,
		Keywords:    matchedKeywords(title + " " + snippet),
	}
}

var rssDateLayouts = []string{
	time.RFC1123Z,
	time.RFC1123,
	"Mon, 2 Jan 2006 15:04:05 MST",
	"Mon, 2 Jan 2006 15:04:05 -0700",
}

func parseRSSDate(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	for _, layout := range rssDateLayouts {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func matchedKeywords(text string) []string {
	lower := strings.ToLower(text)
	var found []string
	for _, kw := range adverseKeywords {
		if strings.Contains(lower, kw) {
			found = append(found, kw)
		}
	}
	return found
}
