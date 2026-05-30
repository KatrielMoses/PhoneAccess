package breach

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

// Snusbase
type snusbaseSource struct{}

func (snusbaseSource) Name() string { return "Snusbase" }

func (snusbaseSource) URL(number *core.PhoneNumber) string {
	return "https://api.snusbase.com/data/search"
}

func (snusbaseSource) PrepareRequest(ctx context.Context, req *http.Request) error {
	key := core.GetAPIKey(ctx, "SNUSBASE_API_KEY")
	if key == "" {
		return fmt.Errorf("api key not configured")
	}
	req.Header.Set("Auth", key)
	req.Header.Set("Content-Type", "application/json")
	
	req.Method = http.MethodPost
	body := map[string]interface{}{
		"terms": []string{e164(core.PhoneNumberFromContext(ctx))},
		"types": []string{"phone"},
	}
	bodyBytes, _ := json.Marshal(body)
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	req.ContentLength = int64(len(bodyBytes))
	return nil
}

type snusbaseResponse struct {
	Results map[string]map[string][]struct {
		Email    string `json:"email"`
		Username string `json:"username"`
		Name     string `json:"name"`
		Password string `json:"password"`
		Hash     string `json:"hash"`
		Database string `json:"database"`
		Created  string `json:"created"`
	} `json:"results"`
	Error string `json:"error"`
}

func (snusbaseSource) Parse(body []byte) SourceResult {
	var resp snusbaseResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return SourceResult{}
	}
	if resp.Error != "" {
		return SourceResult{Error: resp.Error}
	}

	var breaches []BreachEntry
	credentialsFound := false
	for _, termResults := range resp.Results {
		for dbName, records := range termResults {
			for _, rec := range records {
				entry := BreachEntry{
					Name:        firstNonEmpty(rec.Database, dbName),
					Date:        rec.Created,
					SourceAPI:   "Snusbase",
				}
				if rec.Email != "" {
					entry.Emails = []string{rec.Email}
				}
				if rec.Username != "" {
					entry.Usernames = []string{rec.Username}
				}
				if rec.Password != "" || rec.Hash != "" {
					credentialsFound = true
				}
				// Add data classes based on what's available
				var classes []string
				if rec.Email != "" { classes = append(classes, "Email addresses") }
				if rec.Username != "" { classes = append(classes, "Usernames") }
				if rec.Name != "" { classes = append(classes, "Names") }
				if rec.Password != "" || rec.Hash != "" { classes = append(classes, "Passwords") }
				entry.DataClasses = classes
				
				breaches = append(breaches, entry)
			}
		}
	}

	return SourceResult{
		Breaches:         breaches,
		CredentialsFound: credentialsFound,
	}
}

// BreachDirectory
type breachDirectorySource struct{}

func (breachDirectorySource) Name() string { return "BreachDirectory" }

func (breachDirectorySource) URL(number *core.PhoneNumber) string {
	endpoint, _ := url.Parse("https://breachdirectory.p.rapidapi.com/")
	query := endpoint.Query()
	query.Set("func", "auto")
	query.Set("term", e164(number))
	endpoint.RawQuery = query.Encode()
	return endpoint.String()
}

func (breachDirectorySource) PrepareRequest(ctx context.Context, req *http.Request) error {
	key := core.GetAPIKey(ctx, "BREACHDIRECTORY_API_KEY")
	if key == "" {
		return fmt.Errorf("api key not configured")
	}
	req.Header.Set("X-RapidAPI-Key", key)
	req.Header.Set("X-RapidAPI-Host", "breachdirectory.p.rapidapi.com")
	return nil
}

type breachDirectoryResponse struct {
	Success bool `json:"success"`
	Found   int  `json:"found"`
	Result  []struct {
		Sources   []string `json:"sources"`
		Passwords []string `json:"passwords"`
	} `json:"result"`
}

func (breachDirectorySource) Parse(body []byte) SourceResult {
	var resp breachDirectoryResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return SourceResult{}
	}

	var breaches []BreachEntry
	credentialsFound := false
	for _, res := range resp.Result {
		for _, src := range res.Sources {
			breaches = append(breaches, BreachEntry{
				Name:      src,
				SourceAPI: "BreachDirectory",
			})
		}
		if len(res.Passwords) > 0 {
			credentialsFound = true
		}
	}

	return SourceResult{
		Breaches:         breaches,
		CredentialsFound: credentialsFound,
	}
}

// Leak-Lookup
type leakLookupSource struct{}

func (leakLookupSource) Name() string { return "Leak-Lookup" }

func (leakLookupSource) URL(number *core.PhoneNumber) string {
	endpoint, _ := url.Parse("https://leak-lookup.com/api/search")
	query := endpoint.Query()
	query.Set("type", "phone_number")
	query.Set("query", e164(number))
	endpoint.RawQuery = query.Encode()
	return endpoint.String()
}

func (leakLookupSource) PrepareRequest(ctx context.Context, req *http.Request) error {
	key := core.GetAPIKey(ctx, "LEAKLOOKUP_API_KEY")
	if key == "" {
		return fmt.Errorf("api key not configured")
	}
	req.Header.Set("X-API-KEY", key)
	return nil
}

type leakLookupResponse struct {
	Error   string            `json:"error"`
	Message map[string]string `json:"message"`
}

func (leakLookupSource) Parse(body []byte) SourceResult {
	var resp leakLookupResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return SourceResult{}
	}
	if resp.Error == "true" {
		return SourceResult{} // Handle not found or rate limit. If not found, it usually returns error="true" and message="Not Found" or similar.
	}

	var breaches []BreachEntry
	for src := range resp.Message {
		if src != "" {
			breaches = append(breaches, BreachEntry{
				Name:      src,
				SourceAPI: "Leak-Lookup",
			})
		}
	}

	return SourceResult{
		Breaches: breaches,
	}
}

// Scylla.sh
type scyllaSource struct{}

func (scyllaSource) Name() string { return "Scylla.sh" }

func (scyllaSource) URL(number *core.PhoneNumber) string {
	endpoint, _ := url.Parse("https://scylla.sh/search")
	query := endpoint.Query()
	query.Set("q", e164(number))
	query.Set("size", "10")
	endpoint.RawQuery = query.Encode()
	return endpoint.String()
}

func (scyllaSource) PrepareRequest(ctx context.Context, req *http.Request) error {
	return nil // No auth required
}

type scyllaResponse []struct {
	Source struct {
		Email    string `json:"email"`
		Username string `json:"username"`
		Name     string `json:"name"`
		Breach   string `json:"breach"`
	} `json:"_source"`
}

func (scyllaSource) Parse(body []byte) SourceResult {
	var resp scyllaResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return SourceResult{}
	}

	var breaches []BreachEntry
	for _, item := range resp {
		src := item.Source
		entry := BreachEntry{
			Name:      firstNonEmpty(src.Breach, "Scylla Result"),
			SourceAPI: "Scylla.sh",
		}
		var classes []string
		if src.Email != "" {
			entry.Emails = []string{src.Email}
			classes = append(classes, "Email addresses")
		}
		if src.Username != "" {
			entry.Usernames = []string{src.Username}
			classes = append(classes, "Usernames")
		}
		if src.Name != "" {
			classes = append(classes, "Names")
		}
		entry.DataClasses = classes
		breaches = append(breaches, entry)
	}

	return SourceResult{
		Breaches: breaches,
	}
}

func (snusbaseSource) ProxyAware() bool { return true }

func (breachDirectorySource) ProxyAware() bool { return true }

func (leakLookupSource) ProxyAware() bool { return true }

func (scyllaSource) ProxyAware() bool { return true }
