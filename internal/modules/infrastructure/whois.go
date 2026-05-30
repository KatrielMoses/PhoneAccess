package infrastructure

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

// rdapBootstrapResponse is the schema of https://data.iana.org/rdap/dns.json.
type rdapBootstrapResponse struct {
	Services [][][]string `json:"services"`
}

// rdapDomainResponse is the subset of fields we care about from an RDAP domain lookup.
type rdapDomainResponse struct {
	LDHName  string        `json:"ldhName"`
	Events   []rdapEvent   `json:"events"`
	Entities []rdapEntity  `json:"entities"`
}

type rdapEvent struct {
	EventAction string `json:"eventAction"`
	EventDate   string `json:"eventDate"`
}

type rdapEntity struct {
	Roles      []string          `json:"roles"`
	VCardArray []json.RawMessage `json:"vcardArray"`
	Entities   []rdapEntity      `json:"entities"`
}

// queryRDAP queries RDAP/WHOIS for each domain found by crt.sh.
func (m *Module) queryRDAP(ctx context.Context, domains []string) []WhoisHit {
	if len(domains) == 0 {
		return nil
	}

	bootstrap, err := m.loadBootstrap(ctx)
	if err != nil {
		bootstrap = map[string]string{}
	}

	var hits []WhoisHit
	for i, domain := range domains {
		if i > 0 {
			if err := m.rdapLimiter.Wait(ctx, "rdap"); err != nil {
				break
			}
		}

		hit := m.queryOneDomain(ctx, domain, bootstrap)
		if hit != nil {
			hits = append(hits, *hit)
		}
	}
	return hits
}

// loadBootstrap fetches and caches the IANA RDAP bootstrap for the duration of the run.
func (m *Module) loadBootstrap(ctx context.Context) (map[string]string, error) {
	m.bootstrapMu.Lock()
	defer m.bootstrapMu.Unlock()

	if m.bootstrapDone {
		return m.bootstrapData, m.bootstrapErr
	}

	data, err := m.fetchBootstrap(ctx)
	m.bootstrapData = data
	m.bootstrapErr = err
	m.bootstrapDone = true
	return data, err
}

func (m *Module) fetchBootstrap(ctx context.Context) (map[string]string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, core.DefaultHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "https://data.iana.org/rdap/dns.json", nil)
	if err != nil {
		return nil, err
	}
	core.SetDefaultHeaders(req)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RDAP bootstrap: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, err
	}

	var bs rdapBootstrapResponse
	if err := json.Unmarshal(body, &bs); err != nil {
		return nil, err
	}

	result := make(map[string]string, 512)
	for _, service := range bs.Services {
		if len(service) < 2 {
			continue
		}
		tlds, servers := service[0], service[1]
		if len(servers) == 0 {
			continue
		}
		serverBase := strings.TrimSuffix(servers[0], "/")
		for _, tld := range tlds {
			result[strings.ToLower(tld)] = serverBase
		}
	}
	return result, nil
}

// queryOneDomain uses RDAP when bootstrap covers the TLD; falls back to raw
// WHOIS only for TLDs absent from the bootstrap (incomplete RDAP coverage).
func (m *Module) queryOneDomain(ctx context.Context, domain string, bootstrap map[string]string) *WhoisHit {
	tld := domainTLD(domain)
	if server, ok := bootstrap[tld]; ok {
		return m.queryRDAPEndpoint(ctx, domain, server)
	}
	return m.queryWHOISFallback(ctx, domain)
}

func (m *Module) queryRDAPEndpoint(ctx context.Context, domain, serverBase string) *WhoisHit {
	endpoint := serverBase + "/domain/" + domain

	reqCtx, cancel := context.WithTimeout(ctx, core.DefaultHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}
	core.SetDefaultHeaders(req)
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil
	}

	var r rdapDomainResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil
	}
	return extractWhoisFromRDAP(domain, r)
}

func extractWhoisFromRDAP(domain string, r rdapDomainResponse) *WhoisHit {
	hit := &WhoisHit{Domain: domain}

	for _, event := range r.Events {
		switch strings.ToLower(event.EventAction) {
		case "registration":
			hit.RegistrationDate = formatCRTDate(event.EventDate)
		case "expiration":
			hit.ExpiryDate = formatCRTDate(event.EventDate)
		}
	}

	extractRegistrantFromEntities(r.Entities, hit)

	if hit.RegistrantName == "" && hit.RegistrantEmail == "" && hit.RegistrantOrg == "" {
		return nil
	}
	return hit
}

func extractRegistrantFromEntities(entities []rdapEntity, hit *WhoisHit) {
	for _, entity := range entities {
		isRegistrant := false
		for _, role := range entity.Roles {
			if strings.EqualFold(role, "registrant") {
				isRegistrant = true
				break
			}
		}
		if isRegistrant {
			parseVCard(entity.VCardArray, hit)
		}
		extractRegistrantFromEntities(entity.Entities, hit)
	}
}

// parseVCard extracts fn/org/email from a jCard array (vcardArray[1]).
func parseVCard(vcardArray []json.RawMessage, hit *WhoisHit) {
	if len(vcardArray) < 2 {
		return
	}
	var properties []json.RawMessage
	if err := json.Unmarshal(vcardArray[1], &properties); err != nil {
		return
	}

	for _, prop := range properties {
		var parts []json.RawMessage
		if err := json.Unmarshal(prop, &parts); err != nil || len(parts) < 4 {
			continue
		}

		var propName string
		if err := json.Unmarshal(parts[0], &propName); err != nil {
			continue
		}

		switch strings.ToLower(propName) {
		case "fn":
			var value string
			if err := json.Unmarshal(parts[3], &value); err == nil && hit.RegistrantName == "" {
				hit.RegistrantName = strings.TrimSpace(value)
			}
		case "org":
			var value string
			if err := json.Unmarshal(parts[3], &value); err == nil && hit.RegistrantOrg == "" {
				hit.RegistrantOrg = strings.TrimSpace(value)
			}
		case "email":
			var value string
			if err := json.Unmarshal(parts[3], &value); err == nil && hit.RegistrantEmail == "" {
				hit.RegistrantEmail = strings.TrimSpace(value)
			}
		}
	}
}

// queryWHOISFallback performs a raw TCP WHOIS query to whois.iana.org:43.
func (m *Module) queryWHOISFallback(ctx context.Context, domain string) *WhoisHit {
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", "whois.iana.org:43")
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck

	fmt.Fprintf(conn, "%s\r\n", domain) //nolint:errcheck

	hit := &WhoisHit{Domain: domain}
	scanner := bufio.NewScanner(io.LimitReader(conn, 64*1024))

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "%") {
			continue
		}
		kv := strings.SplitN(line, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])

		switch key {
		case "registrant name", "registrant-name":
			if hit.RegistrantName == "" {
				hit.RegistrantName = val
			}
		case "registrant organization", "registrant-organization", "registrant org":
			if hit.RegistrantOrg == "" {
				hit.RegistrantOrg = val
			}
		case "registrant email", "registrant-email":
			if hit.RegistrantEmail == "" {
				hit.RegistrantEmail = val
			}
		case "creation date", "created":
			if hit.RegistrationDate == "" {
				hit.RegistrationDate = formatCRTDate(val)
			}
		case "registry expiry date", "expiry date", "expires":
			if hit.ExpiryDate == "" {
				hit.ExpiryDate = formatCRTDate(val)
			}
		}
	}

	if hit.RegistrantName == "" && hit.RegistrantEmail == "" && hit.RegistrantOrg == "" {
		return nil
	}
	return hit
}

func domainTLD(domain string) string {
	parts := strings.Split(strings.ToLower(domain), ".")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-1]
}
