package infrastructure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

type crtEntry struct {
	ID             int64  `json:"id"`
	IssuerCAID     int64  `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	EntryTimestamp string `json:"entry_timestamp"`
}

// queryCRT queries crt.sh for each search variant of the phone number.
// Returns cert hits and the deduplicated list of discovered domains.
func (m *Module) queryCRT(ctx context.Context, number *core.PhoneNumber) ([]CertHit, []string) {
	queries := crtQueryVariants(number)

	seenDomains := map[string]bool{}
	seenCertKey := map[string]bool{}
	var hits []CertHit

	for i, query := range queries {
		if i > 0 {
			if err := m.crtLimiter.Wait(ctx, "crt.sh"); err != nil {
				break
			}
		}

		entries, err := m.fetchCRTEntries(ctx, query)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			domains := extractDomainsFromCRTEntry(entry)
			for _, domain := range domains {
				if seenDomains[domain] {
					continue
				}
				seenDomains[domain] = true

				key := strings.ToLower(domain) + "|" + entry.NotBefore
				if seenCertKey[key] {
					continue
				}
				seenCertKey[key] = true

				hits = append(hits, CertHit{
					Domain:         domain,
					Issuer:         extractCAName(entry.IssuerName),
					IssuedAt:       formatCRTDate(entry.NotBefore),
					ExpiresAt:      formatCRTDate(entry.NotAfter),
					EntryTimestamp: formatCRTDate(entry.EntryTimestamp),
				})
			}
		}
	}

	domains := make([]string, 0, len(seenDomains))
	for d := range seenDomains {
		domains = append(domains, d)
	}
	return hits, domains
}

func (m *Module) fetchCRTEntries(ctx context.Context, query string) ([]crtEntry, error) {
	endpoint, _ := url.Parse("https://crt.sh/")
	q := endpoint.Query()
	q.Set("q", query)
	q.Set("output", "json")
	endpoint.RawQuery = q.Encode()

	reqCtx, cancel := context.WithTimeout(ctx, core.DefaultHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	core.SetDefaultHeaders(req)
	req.Header.Set("Accept", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("crt.sh: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, err
	}

	var entries []crtEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// crtQueryVariants returns E164 plus all SearchVariants, deduplicated.
func crtQueryVariants(number *core.PhoneNumber) []string {
	seen := map[string]bool{}
	var queries []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			queries = append(queries, v)
		}
	}
	add(number.E164)
	for _, v := range number.SearchVariants {
		add(v)
	}
	return queries
}

// extractDomainsFromCRTEntry pulls distinct hostnames from common_name and name_value.
func extractDomainsFromCRTEntry(entry crtEntry) []string {
	seen := map[string]bool{}
	var domains []string

	addCandidate := func(candidate string) {
		candidate = strings.TrimSpace(strings.TrimPrefix(candidate, "*."))
		candidate = strings.ToLower(candidate)
		if candidate == "" || !strings.Contains(candidate, ".") {
			return
		}
		// Skip if it still contains a wildcard or looks like a phone number
		if strings.ContainsAny(candidate, "*+()") {
			return
		}
		if !seen[candidate] {
			seen[candidate] = true
			domains = append(domains, candidate)
		}
	}

	addCandidate(entry.CommonName)
	for _, line := range strings.Split(entry.NameValue, "\n") {
		for _, part := range strings.Fields(line) {
			addCandidate(part)
		}
	}
	return domains
}

// extractCAName pulls the O= value from an X.509 DN string.
func extractCAName(issuerDN string) string {
	for _, part := range strings.Split(issuerDN, ",") {
		part = strings.TrimSpace(part)
		upper := strings.ToUpper(part)
		if strings.HasPrefix(upper, "O=") {
			return strings.TrimSpace(part[2:])
		}
	}
	return issuerDN
}

// formatCRTDate normalises various timestamp formats to YYYY-MM-DD.
func formatCRTDate(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, value); err == nil {
			return t.Format("2006-01-02")
		}
	}
	return value
}
