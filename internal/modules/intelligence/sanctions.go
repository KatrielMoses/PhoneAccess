package intelligence

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

const (
	opensanctionsSearchURL = "https://api.opensanctions.org/search/default"
	opensanctionsMatchURL  = "https://api.opensanctions.org/match/default"
	sanctionsScoreMin      = 0.60
	sanctionsHighRiskScore = 0.85
	maxSanctionsBody       = 4 * 1024 * 1024
)

// knownLists are the major sanctions/PEP datasets OpenSanctions aggregates.
var knownLists = []string{
	"OFAC SDN", "OFAC Non-SDN", "UN Consolidated", "EU Consolidated",
	"UK HMT", "INTERPOL Red Notices", "World Bank Debarment", "BIS Entity List",
}

// opensanctionsKey returns the configured API key, empty string if absent.
func opensanctionsKey() string {
	return strings.TrimSpace(os.Getenv("OPENSANCTIONS_API_KEY"))
}

// osSearchResponse is the shape returned by the unauthenticated search endpoint.
type osSearchResponse struct {
	Results []osEntity `json:"results"`
}

// osMatchResponse is the shape returned by the authenticated match endpoint.
type osMatchResponse struct {
	Responses map[string]struct {
		Results []osEntity `json:"results"`
	} `json:"responses"`
}

type osEntity struct {
	ID         string              `json:"id"`
	Schema     string              `json:"schema"`
	Properties map[string][]string `json:"properties"`
	Datasets   []string            `json:"datasets"`
	Score      float64             `json:"score"`
}

func (m *Module) fetchSanctions(ctx context.Context, number *core.PhoneNumber) SanctionsResult {
	result := SanctionsResult{
		ListsChecked: knownLists,
	}

	var allEntities []osEntity

	// Always attempt the unauthenticated search endpoint.
	result.Screened = m.searchSanctions(ctx, number.E164, &allEntities)

	// If an API key is present, also run the richer match endpoint.
	if key := opensanctionsKey(); key != "" {
		m.matchSanctions(ctx, key, number.E164, &allEntities)
	}

	seen := map[string]bool{}
	for _, entity := range allEntities {
		if entity.Score < sanctionsScoreMin {
			continue
		}
		if seen[entity.ID] {
			continue
		}
		seen[entity.ID] = true

		hit := SanctionsHit{
			EntityID:  entity.ID,
			Name:      firstProperty(entity.Properties, "name"),
			Datasets:  friendlyDatasets(entity.Datasets),
			Score:     entity.Score,
			Position:  firstProperty(entity.Properties, "position"),
			BirthDate: firstProperty(entity.Properties, "birthDate"),
		}
		nat := firstProperty(entity.Properties, "nationality")
		if nat == "" {
			nat = firstProperty(entity.Properties, "country")
		}
		hit.Nationality = nat

		result.Hits = append(result.Hits, hit)
		if entity.Score >= sanctionsHighRiskScore {
			result.HighRisk = true
		}
	}

	return result
}

// searchSanctions queries the unauthenticated search endpoint.
// Returns true if the request succeeded (even with zero results).
func (m *Module) searchSanctions(ctx context.Context, e164 string, out *[]osEntity) bool {
	params := url.Values{}
	params.Set("q", e164)
	params.Set("schema", "Person")
	reqURL := opensanctionsSearchURL + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	var payload osSearchResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxSanctionsBody)).Decode(&payload); err != nil {
		return false
	}
	*out = append(*out, payload.Results...)
	return true
}

// matchSanctions queries the authenticated match endpoint.
func (m *Module) matchSanctions(ctx context.Context, apiKey, e164 string, out *[]osEntity) {
	body := map[string]any{
		"queries": map[string]any{
			"phone_query": map[string]any{
				"schema": "Person",
				"properties": map[string]any{
					"phone": []string{e164},
				},
			},
		},
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, opensanctionsMatchURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "ApiKey "+apiKey)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	var payload osMatchResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxSanctionsBody)).Decode(&payload); err != nil {
		return
	}
	for _, group := range payload.Responses {
		*out = append(*out, group.Results...)
	}
}

// firstProperty returns the first non-empty value for a given property key.
func firstProperty(props map[string][]string, key string) string {
	for _, v := range props[key] {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
}

// datasetAliases maps OpenSanctions dataset IDs to friendly short names.
var datasetAliases = map[string]string{
	"us_ofac_sdn":          "OFAC SDN",
	"us_ofac_cons":         "OFAC Non-SDN",
	"un_sc_sanctions":      "UN",
	"eu_fsf":               "EU",
	"eu_eeas_sanctions":    "EU",
	"gb_hmt_sanctions":     "UK HMT",
	"interpol_red_notices": "INTERPOL",
	"worldbank_debarment":  "World Bank",
	"us_bis_entities":      "BIS",
}

// friendlyDatasets converts dataset IDs to display names, deduplicating.
func friendlyDatasets(datasets []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(datasets))
	for _, ds := range datasets {
		name, ok := datasetAliases[ds]
		if !ok {
			name = ds
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}
