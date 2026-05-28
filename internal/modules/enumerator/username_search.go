package enumerator

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

type UsernameProfileHit struct {
	Platform   string
	URL        string
	Source     string
	Confidence float64
}

func Services() []Service {
	return append([]Service(nil), allServices()...)
}

func SearchUsernameProfiles(ctx context.Context, client HTTPClient, services []Service, username string, limiter *core.RateLimiter) ([]UsernameProfileHit, error) {
	username = normalizeUsername(username)
	if username == "" {
		return nil, nil
	}
	if client == nil {
		client = core.NewHTTPClient(core.DefaultHTTPTimeout)
	}
	hits := make([]UsernameProfileHit, 0)
	seen := map[string]bool{}

	for _, service := range services {
		candidates := profileCandidates(service, username)
		found := false
		for _, candidate := range candidates {
			key := strings.ToLower(service.Name + "|" + candidate)
			if seen[key] {
				continue
			}
			seen[key] = true
			if limiter != nil {
				if err := limiter.Wait(ctx, hostFromURL(candidate)); err != nil {
					return nil, err
				}
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, candidate, nil)
			if err != nil {
				continue
			}
			core.SetDefaultHeaders(req)
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			func() {
				defer resp.Body.Close()
				if resp.StatusCode < 200 || resp.StatusCode >= 400 {
					return
				}
				hits = append(hits, UsernameProfileHit{
					Platform:   service.Name,
					URL:        candidate,
					Source:     "username_profile",
					Confidence: 1.0,
				})
				found = true
			}()
			if found {
				break
			}
		}
	}

	return dedupeUsernameProfileHits(hits), nil
}

func profileCandidates(service Service, username string) []string {
	host := serviceHost(service)
	if host == "" {
		return nil
	}
	pathTemplates := []string{
		"/%s",
		"/@%s",
		"/users/%s",
		"/u/%s",
		"/profile/%s",
	}
	candidates := make([]string, 0, len(pathTemplates)+1)
	for _, tmpl := range pathTemplates {
		candidates = append(candidates, fmt.Sprintf("https://%s%s", host, fmt.Sprintf(tmpl, url.PathEscape(username))))
	}
	if trimmed := strings.TrimPrefix(host, "www."); trimmed != host {
		for _, tmpl := range pathTemplates {
			candidates = append(candidates, fmt.Sprintf("https://%s%s", trimmed, fmt.Sprintf(tmpl, url.PathEscape(username))))
		}
	}
	return uniqueStrings(candidates)
}

func serviceHost(service Service) string {
	parsed, err := url.Parse(service.URL)
	if err != nil {
		return ""
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	host = strings.TrimPrefix(host, "api.")
	host = strings.TrimPrefix(host, "www.")
	host = strings.TrimPrefix(host, "m.")
	host = strings.TrimPrefix(host, "mobile.")
	host = strings.TrimPrefix(host, "login.")
	host = strings.TrimPrefix(host, "accounts.")
	return host
}

func normalizeUsername(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "@")
	return strings.Join(strings.Fields(value), "")
}

func dedupeUsernameProfileHits(hits []UsernameProfileHit) []UsernameProfileHit {
	seen := map[string]bool{}
	out := make([]UsernameProfileHit, 0, len(hits))
	for _, hit := range hits {
		key := strings.ToLower(hit.Platform + "|" + hit.URL)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, hit)
	}
	return out
}

func hostFromURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func uniqueStrings(values []string) []string {
	seen := map[string]string{}
	for _, value := range values {
		cleaned := strings.TrimSpace(value)
		if cleaned == "" {
			continue
		}
		seen[strings.ToLower(cleaned)] = cleaned
	}
	out := make([]string, 0, len(seen))
	for _, value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
