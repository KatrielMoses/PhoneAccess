package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/config"
	"github.com/KatrielMoses/PhoneAccess/internal/core"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/enumerator"
	"github.com/KatrielMoses/PhoneAccess/internal/storage"
	"github.com/spf13/cobra"
)

// pivotShared holds flags shared by all pivot subcommands via PersistentFlags.
type pivotShared struct {
	caseID int64
	format string
	noSave bool
}

// PivotUsernameResult is the JSON-serialisable result of a username pivot.
type PivotUsernameResult struct {
	Username        string                        `json:"username"`
	Hits            []enumerator.UsernameProfileHit `json:"hits"`
	ServicesChecked int                           `json:"services_checked"`
}

// PivotDomainResult is the JSON-serialisable result of a domain pivot.
type PivotDomainResult struct {
	Domain           string         `json:"domain"`
	Certificates     []pivotCertHit `json:"certificates"`
	Registrant       string         `json:"registrant,omitempty"`
	RegistrantEmail  string         `json:"registrant_email,omitempty"`
	RegistrationDate string         `json:"registration_date,omitempty"`
	VTConfigured     bool           `json:"vt_configured"`
	VTThreatCount    int            `json:"vt_threat_count"`
	VTLabels         []string       `json:"vt_labels,omitempty"`
}

type pivotCertHit struct {
	Domain   string `json:"domain"`
	Issuer   string `json:"issuer,omitempty"`
	IssuedAt string `json:"issued_at,omitempty"`
}

// ────────────────────────────────────────────────────────────────────────────
// Command construction
// ────────────────────────────────────────────────────────────────────────────

func newPivotCommand(o *options) *cobra.Command {
	p := &pivotShared{format: "terminal"}

	cmd := &cobra.Command{
		Use:          "pivot <type> <value>",
		Short:        "Pivot from a discovered artifact to related intelligence",
		SilenceUsage: true,
	}

	cmd.PersistentFlags().Int64Var(&p.caseID, "case", 0, "link pivot to parent case ID in SQLite")
	cmd.PersistentFlags().StringVar(&p.format, "format", "terminal", "output format: terminal or json")
	cmd.PersistentFlags().BoolVar(&p.noSave, "no-save", false, "skip database persistence")

	cmd.AddCommand(newPivotEmailCmd(o, p))
	cmd.AddCommand(newPivotUsernameCmd(o, p))
	cmd.AddCommand(newPivotDomainCmd(o, p))
	cmd.AddCommand(newPivotNameCmd(o, p))
	cmd.AddCommand(newPivotPhoneCmd(o, p))

	return cmd
}

// ────────────────────────────────────────────────────────────────────────────
// pivot email
// ────────────────────────────────────────────────────────────────────────────

func newPivotEmailCmd(o *options, p *pivotShared) *cobra.Command {
	return &cobra.Command{
		Use:          "email <address>",
		Short:        "Pivot from an email address (suggestion + search/breach/paste modules)",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPivotEmail(cmd.Context(), cmd.OutOrStdout(), o, p, args[0])
		},
	}
}

func runPivotEmail(ctx context.Context, out io.Writer, o *options, p *pivotShared, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))

	if strings.ToLower(p.format) != "json" {
		printPivotEmailSuggestion(out, email)
	}

	// Build a stub PhoneNumber so search/breach/paste modules receive the
	// email as their query term rather than a real phone number.
	stub := &core.PhoneNumber{
		RawInput:       email,
		E164:           email,
		SearchVariants: []string{email},
		Valid:           false,
	}

	selected := selectModulesByNames(o.allModules, "breach", "search", "paste")
	engine := core.NewEngine(
		selected,
		core.WithModuleTimeout(time.Duration(o.timeoutSecs)*time.Second),
		core.WithPassive(true),
	)
	report, err := engine.Run(ctx, stub)
	if err != nil {
		return err
	}

	if !p.noSave {
		link := pivotLink(p, "email", email)
		if _, err := o.saveInvestigationToDB(report, out, link, false); err != nil {
			return err
		}
	}

	if strings.ToLower(p.format) == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	_, err = io.WriteString(out, NewTerminalRenderer(o.minConfidence).Render(report))
	return err
}

// printPivotEmailSuggestion writes the MailAccess suggestion block to w.
func printPivotEmailSuggestion(w io.Writer, email string) {
	fmt.Fprintln(w, "→ Pivot: email address discovered")
	fmt.Fprintln(w, "  Run: mailaccess investigate "+email)
	fmt.Fprintln(w, "  Or:  phoneaccess investigate --modules breach,search,paste "+email)
	fmt.Fprintln(w)
}

// ────────────────────────────────────────────────────────────────────────────
// pivot username
// ────────────────────────────────────────────────────────────────────────────

func newPivotUsernameCmd(o *options, p *pivotShared) *cobra.Command {
	return &cobra.Command{
		Use:          "username <handle>",
		Short:        "Search for a username across social platforms",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPivotUsername(cmd.Context(), cmd.OutOrStdout(), o, p, args[0])
		},
	}
}

func runPivotUsername(ctx context.Context, out io.Writer, o *options, p *pivotShared, username string) error {
	client := core.NewHTTPClient(core.DefaultHTTPTimeout)
	services := enumerator.Services()
	limiter := core.NewRateLimiter(2 * time.Second)

	hits, err := enumerator.SearchUsernameProfiles(ctx, client, services, username, limiter)
	if err != nil {
		return err
	}

	result := PivotUsernameResult{
		Username:        username,
		Hits:            hits,
		ServicesChecked: len(services),
	}

	if !p.noSave {
		savePivotNonPhone(p, "username", username, result)
	}

	if strings.ToLower(p.format) == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}
	return renderPivotUsername(out, result)
}

func renderPivotUsername(out io.Writer, r PivotUsernameResult) error {
	fmt.Fprintf(out, "\nUSERNAME PIVOT: %s\n", r.Username)
	fmt.Fprintf(out, "  Services checked: %d\n", r.ServicesChecked)
	if len(r.Hits) == 0 {
		fmt.Fprintln(out, "  No profiles found.")
		return nil
	}
	fmt.Fprintf(out, "  Platforms found: %d\n", len(r.Hits))
	for _, hit := range r.Hits {
		fmt.Fprintf(out, "  ✓ %-20s  %s\n", hit.Platform, hit.URL)
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
// pivot domain
// ────────────────────────────────────────────────────────────────────────────

func newPivotDomainCmd(o *options, p *pivotShared) *cobra.Command {
	return &cobra.Command{
		Use:          "domain <domain>",
		Short:        "Run certificate, WHOIS/RDAP, and VirusTotal lookups against a domain",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPivotDomain(cmd.Context(), cmd.OutOrStdout(), o, p, args[0])
		},
	}
}

func runPivotDomain(ctx context.Context, out io.Writer, o *options, p *pivotShared, domain string) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	client := core.NewHTTPClient(core.DefaultHTTPTimeout)

	store, _ := config.NewDefaultStore()
	vtKey := resolveConfig(store, "VIRUSTOTAL_API_KEY")

	result := PivotDomainResult{Domain: domain}

	// crt.sh — SSL certificate transparency.
	if certs, err := queryCRTForDomain(ctx, client, domain); err == nil {
		result.Certificates = certs
	}

	// RDAP/WHOIS — registrant information.
	registrant, registrantEmail, regDate := queryRDAPForDomain(ctx, client, domain)
	result.Registrant = registrant
	result.RegistrantEmail = registrantEmail
	result.RegistrationDate = regDate

	// VirusTotal — domain threat intelligence.
	if vtKey != "" {
		result.VTConfigured = true
		count, labels := queryVTForDomain(ctx, client, domain, vtKey)
		result.VTThreatCount = count
		result.VTLabels = labels
	}

	if !p.noSave {
		savePivotNonPhone(p, "domain", domain, result)
	}

	if strings.ToLower(p.format) == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}
	return renderPivotDomain(out, result)
}

func renderPivotDomain(out io.Writer, r PivotDomainResult) error {
	fmt.Fprintf(out, "\nDOMAIN PIVOT: %s\n", r.Domain)
	if len(r.Certificates) == 0 {
		fmt.Fprintln(out, "  Certificates:  no hits")
	} else {
		fmt.Fprintf(out, "  Certificates:  %d domain(s) found via SSL CT logs\n", len(r.Certificates))
		for _, c := range r.Certificates {
			line := "  ✓ " + c.Domain
			if c.IssuedAt != "" {
				line += " (issued " + c.IssuedAt
				if c.Issuer != "" {
					line += ", " + c.Issuer
				}
				line += ")"
			}
			fmt.Fprintln(out, line)
		}
	}

	if r.Registrant != "" || r.RegistrantEmail != "" {
		parts := []string{}
		if r.Registrant != "" {
			parts = append(parts, "Registrant: "+r.Registrant)
		}
		if r.RegistrantEmail != "" {
			parts = append(parts, r.RegistrantEmail)
		}
		if r.RegistrationDate != "" {
			parts = append(parts, r.RegistrationDate)
		}
		fmt.Fprintf(out, "  WHOIS:         %s\n", strings.Join(parts, ", "))
	} else {
		fmt.Fprintln(out, "  WHOIS:         no registrant data")
	}

	if !r.VTConfigured {
		fmt.Fprintln(out, "  VirusTotal:    not configured (set VIRUSTOTAL_API_KEY)")
	} else if r.VTThreatCount > 0 {
		labels := ""
		if len(r.VTLabels) > 0 {
			labels = " — " + strings.Join(r.VTLabels, ", ")
		}
		fmt.Fprintf(out, "  VirusTotal:    %d hit(s)%s\n", r.VTThreatCount, labels)
	} else {
		fmt.Fprintln(out, "  VirusTotal:    no hits")
	}
	return nil
}

// queryCRTForDomain queries crt.sh certificate transparency logs for a domain.
func queryCRTForDomain(ctx context.Context, client *http.Client, domain string) ([]pivotCertHit, error) {
	endpoint := "https://crt.sh/?q=" + url.QueryEscape(domain) + "&output=json"
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
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

	var entries []struct {
		CommonName string `json:"common_name"`
		NameValue  string `json:"name_value"`
		IssuerName string `json:"issuer_name"`
		NotBefore  string `json:"not_before"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	hits := make([]pivotCertHit, 0, len(entries))
	for _, e := range entries {
		names := strings.Split(e.NameValue, "\n")
		names = append(names, e.CommonName)
		for _, n := range names {
			n = strings.TrimSpace(strings.TrimPrefix(n, "*."))
			if n == "" || seen[n] {
				continue
			}
			seen[n] = true
			issuedAt := ""
			if len(e.NotBefore) >= 10 {
				issuedAt = e.NotBefore[:10]
			}
			issuer := extractCNFromIssuer(e.IssuerName)
			hits = append(hits, pivotCertHit{Domain: n, Issuer: issuer, IssuedAt: issuedAt})
		}
	}
	return hits, nil
}

func extractCNFromIssuer(issuerName string) string {
	for _, part := range strings.Split(issuerName, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "CN=") {
			return strings.TrimPrefix(strings.TrimPrefix(part, "CN="), "cn=")
		}
	}
	return ""
}

// queryRDAPForDomain queries the rdap.org proxy for WHOIS/RDAP registrant data.
func queryRDAPForDomain(ctx context.Context, client *http.Client, domain string) (registrant, registrantEmail, regDate string) {
	endpoint := "https://rdap.org/domain/" + url.PathEscape(domain)
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return
	}
	core.SetDefaultHeaders(req)
	req.Header.Set("Accept", "application/rdap+json, application/json")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var result struct {
		Events []struct {
			EventAction string `json:"eventAction"`
			EventDate   string `json:"eventDate"`
		} `json:"events"`
		Entities []struct {
			Roles      []string        `json:"roles"`
			VCardArray []json.RawMessage `json:"vcardArray"`
		} `json:"entities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return
	}

	for _, ev := range result.Events {
		if ev.EventAction == "registration" && len(ev.EventDate) >= 10 {
			regDate = ev.EventDate[:10]
		}
	}
	for _, entity := range result.Entities {
		isRegistrant := false
		for _, role := range entity.Roles {
			if strings.EqualFold(role, "registrant") {
				isRegistrant = true
				break
			}
		}
		if !isRegistrant {
			continue
		}
		registrant, registrantEmail = extractVCardFields(entity.VCardArray)
		if registrant != "" {
			break
		}
	}
	return
}

func extractVCardFields(vcardArray []json.RawMessage) (name, email string) {
	if len(vcardArray) < 2 {
		return
	}
	var props []json.RawMessage
	if err := json.Unmarshal(vcardArray[1], &props); err != nil {
		return
	}
	for _, prop := range props {
		var parts []json.RawMessage
		if err := json.Unmarshal(prop, &parts); err != nil || len(parts) < 4 {
			continue
		}
		var propName string
		if err := json.Unmarshal(parts[0], &propName); err != nil {
			continue
		}
		var value string
		if err := json.Unmarshal(parts[3], &value); err != nil {
			continue
		}
		switch strings.ToLower(propName) {
		case "fn":
			name = value
		case "email":
			email = value
		}
	}
	return
}

// queryVTForDomain queries VirusTotal's domain endpoint.
func queryVTForDomain(ctx context.Context, client *http.Client, domain, apiKey string) (threatCount int, labels []string) {
	endpoint := "https://www.virustotal.com/api/v3/domains/" + url.PathEscape(domain)
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return
	}
	core.SetDefaultHeaders(req)
	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var result struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
				} `json:"last_analysis_stats"`
				Tags []string `json:"tags"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return
	}

	attrs := result.Data.Attributes
	threatCount = attrs.LastAnalysisStats.Malicious + attrs.LastAnalysisStats.Suspicious
	labels = attrs.Tags
	return
}

// ────────────────────────────────────────────────────────────────────────────
// pivot name
// ────────────────────────────────────────────────────────────────────────────

func newPivotNameCmd(o *options, p *pivotShared) *cobra.Command {
	return &cobra.Command{
		Use:          "name <full-name>",
		Short:        "Search for phone numbers associated with a name",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPivotName(cmd.Context(), cmd.OutOrStdout(), o, p, args[0])
		},
	}
}

func runPivotName(ctx context.Context, out io.Writer, o *options, p *pivotShared, name string) error {
	name = strings.TrimSpace(name)

	// Construct dork variants that the search module will use.
	stub := &core.PhoneNumber{
		RawInput:       name,
		E164:           name,
		SearchVariants: []string{`"` + name + `" phone`, `"` + name + `" phone number`},
		Valid:           false,
	}

	selected := selectModulesByNames(o.allModules, "search")
	engine := core.NewEngine(
		selected,
		core.WithModuleTimeout(time.Duration(o.timeoutSecs)*time.Second),
		core.WithPassive(true),
	)
	report, err := engine.Run(ctx, stub)
	if err != nil {
		return err
	}

	if !p.noSave {
		link := pivotLink(p, "name", name)
		if _, err := o.saveInvestigationToDB(report, out, link, false); err != nil {
			return err
		}
	}

	if strings.ToLower(p.format) == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	fmt.Fprintf(out, "\nNAME PIVOT: %s\n", name)
	_, err = io.WriteString(out, NewTerminalRenderer(o.minConfidence).Render(report))
	return err
}

// ────────────────────────────────────────────────────────────────────────────
// pivot phone
// ────────────────────────────────────────────────────────────────────────────

func newPivotPhoneCmd(o *options, p *pivotShared) *cobra.Command {
	var active bool
	var yes bool
	var timeoutSecs int
	var compact bool
	var field bool
	cmd := &cobra.Command{
		Use:          "phone <number>",
		Short:        "Run a passive investigation on a second phone number",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if compact && field {
				return errors.New("--compact and --field are mutually exclusive")
			}
			if compact {
				p.format = "compact"
			} else if field {
				p.format = "field"
			}
			return runPivotPhone(cmd.Context(), cmd.OutOrStdout(), o, p, args[0], active, yes, timeoutSecs)
		},
	}
	cmd.Flags().BoolVar(&active, "active", false, "include active modules (default: passive only)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip OPSEC pre-flight prompt (for non-interactive/scripted use)")
	cmd.Flags().IntVar(&timeoutSecs, "timeout", 30, "per-module timeout in seconds")
	cmd.Flags().BoolVar(&compact, "compact", false, "compact triage output (≤6 lines); alias for --format compact")
	cmd.Flags().BoolVar(&field, "field", false, "pipe-delimited single line for scripting; alias for --format field")
	return cmd
}

func runPivotPhone(ctx context.Context, out io.Writer, o *options, p *pivotShared, rawPhone string, active, yes bool, timeoutSecs int) error {
	number, err := core.NormalizePhoneNumber(rawPhone)
	if err != nil {
		return fmt.Errorf("invalid phone number: %w", err)
	}

	passive := !active
	selected, err := selectModules(o.allModules, "")
	if err != nil {
		return err
	}

	if active && !yes {
		localOpts := *o
		localOpts.active = true
		localOpts.yes = false
		if err := printOpsecWarning(out, buildOpsecState(&localOpts)); err != nil {
			return err
		}
	}

	if timeoutSecs <= 0 {
		timeoutSecs = 30
	}

	engine := core.NewEngine(
		selected,
		core.WithModuleTimeout(time.Duration(timeoutSecs)*time.Second),
		core.WithPassive(passive),
		core.WithActive(active),
		core.WithIdentityRecordBuilder(defaultIdentityBuilder(passive, true)),
	)
	report, err := engine.Run(ctx, number)
	if err != nil {
		return err
	}

	if !p.noSave {
		link := pivotLink(p, "phone", rawPhone)
		if _, err := o.saveInvestigationToDB(report, out, link, false); err != nil {
			return err
		}
	}

	switch strings.ToLower(p.format) {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	case "compact":
		_, err = io.WriteString(out, NewCompactRenderer().Render(report))
		return err
	case "field":
		_, err = io.WriteString(out, NewFieldRenderer().Render(report))
		return err
	default:
		_, err = io.WriteString(out, NewTerminalRenderer(o.minConfidence).Render(report))
		return err
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ────────────────────────────────────────────────────────────────────────────

// selectModulesByNames returns the registry with only the named modules active
// (others are wrapped as skipped stubs).
func selectModulesByNames(registry []core.Module, names ...string) []core.Module {
	target := make(map[string]bool, len(names))
	for _, n := range names {
		target[n] = true
	}
	out := make([]core.Module, 0, len(registry))
	for _, m := range registry {
		if target[m.Name()] {
			out = append(out, m)
		} else {
			out = append(out, skippedModule{name: m.Name(), description: m.Description()})
		}
	}
	return out
}

// pivotLink constructs an InvestigationLink for case attachment (zero if no case).
func pivotLink(p *pivotShared, pivotType, pivotValue string) storage.InvestigationLink {
	if p.caseID <= 0 {
		return storage.InvestigationLink{}
	}
	return storage.InvestigationLink{
		ParentID:   p.caseID,
		PivotType:  pivotType,
		PivotValue: pivotValue,
		Depth:      1,
	}
}

// savePivotNonPhone persists a non-phone pivot result to SQLite.
func savePivotNonPhone(p *pivotShared, pivotType, pivotValue string, data any) {
	s, err := storage.Open("")
	if err != nil {
		return
	}
	defer s.Close()

	reportJSON, err := json.Marshal(data)
	if err != nil {
		return
	}

	key := pivotType + ":" + pivotValue
	link := pivotLink(p, pivotType, pivotValue)
	_, _, _ = s.SaveInvestigation(key, string(reportJSON), 0, "", nil, link)
}
