package infrastructure

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

type vtSearchResponse struct {
	Data []vtObject `json:"data"`
}

type vtObject struct {
	Type       string       `json:"type"`
	ID         string       `json:"id"`
	Attributes vtAttributes `json:"attributes"`
}

type vtAttributes struct {
	LastAnalysisResults map[string]vtEngineResult `json:"last_analysis_results"`
	Tags                []string                  `json:"tags"`
	Domains             []string                  `json:"domains,omitempty"`
	IPAddresses         []string                  `json:"ip_addresses,omitempty"`
}

type vtEngineResult struct {
	Category string `json:"category"`
	Result   string `json:"result"`
}

// queryVT searches VirusTotal for the phone number's E164 form.
// The vtLimiter enforces the 15-second exact rate limit with no jitter.
func (m *Module) queryVT(ctx context.Context, number *core.PhoneNumber, apiKey string) *VTHit {
	if apiKey == "" {
		return nil
	}

	if err := m.vtLimiter.Wait(ctx); err != nil {
		return nil
	}

	endpoint, _ := url.Parse("https://www.virustotal.com/api/v3/search")
	q := endpoint.Query()
	q.Set("query", number.E164)
	endpoint.RawQuery = q.Encode()

	reqCtx, cancel := context.WithTimeout(ctx, core.DefaultHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil
	}
	core.SetDefaultHeaders(req)
	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("Accept", "application/json")

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

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil
	}

	var vtResp vtSearchResponse
	if err := json.Unmarshal(body, &vtResp); err != nil || len(vtResp.Data) == 0 {
		return nil
	}

	hit := &VTHit{
		Query:    number.E164,
		HitCount: len(vtResp.Data),
	}

	labelSet := map[string]bool{}
	domainSet := map[string]bool{}
	ipSet := map[string]bool{}

	for _, obj := range vtResp.Data {
		for engine, result := range obj.Attributes.LastAnalysisResults {
			if result.Category == "malicious" || result.Category == "suspicious" {
				label := engine
				if result.Result != "" {
					label += ":" + result.Result
				}
				labelSet[label] = true
			}
		}
		for _, tag := range obj.Attributes.Tags {
			if tag != "" {
				labelSet[tag] = true
			}
		}
		for _, d := range obj.Attributes.Domains {
			if d != "" {
				domainSet[d] = true
			}
		}
		for _, ip := range obj.Attributes.IPAddresses {
			if ip != "" {
				ipSet[ip] = true
			}
		}
	}

	hit.ThreatLabels = sortedKeys(labelSet)
	hit.AssociatedDomains = sortedKeys(domainSet)
	hit.AssociatedIPs = sortedKeys(ipSet)

	return hit
}
