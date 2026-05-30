package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/config"
	"github.com/KatrielMoses/PhoneAccess/internal/core"
	"github.com/KatrielMoses/PhoneAccess/internal/correlator"
	"github.com/KatrielMoses/PhoneAccess/internal/exporters"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/enumerator"
	publicrecords "github.com/KatrielMoses/PhoneAccess/internal/modules/publicrecords"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/social/telegram"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/social/whatsapp"
	"github.com/KatrielMoses/PhoneAccess/internal/sources"
	"github.com/KatrielMoses/PhoneAccess/internal/sources/abstractapi"
	"github.com/KatrielMoses/PhoneAccess/internal/sources/callerkit"
	companieshouse "github.com/KatrielMoses/PhoneAccess/internal/sources/companies_house"
	"github.com/KatrielMoses/PhoneAccess/internal/sources/dastelefon"
	"github.com/KatrielMoses/PhoneAccess/internal/sources/ipqs"
	"github.com/KatrielMoses/PhoneAccess/internal/sources/leaksight"
	"github.com/KatrielMoses/PhoneAccess/internal/sources/neutrino"
	"github.com/KatrielMoses/PhoneAccess/internal/sources/nigeriaphonebook"
	"github.com/KatrielMoses/PhoneAccess/internal/sources/numlookup"
	"github.com/KatrielMoses/PhoneAccess/internal/sources/opencnam"
	paginasblancasar "github.com/KatrielMoses/PhoneAccess/internal/sources/paginasblancas_ar"
	"github.com/KatrielMoses/PhoneAccess/internal/sources/paginebianche"
	"github.com/KatrielMoses/PhoneAccess/internal/sources/telelistas"
	"github.com/KatrielMoses/PhoneAccess/internal/sources/trestle"
	"github.com/KatrielMoses/PhoneAccess/internal/sources/twilio"
	"github.com/KatrielMoses/PhoneAccess/internal/sources/veriphone"
	"github.com/KatrielMoses/PhoneAccess/internal/storage"
	"github.com/spf13/cobra"
)

type options struct {
	format       string
	moduleNames  string
	passive      bool
	active       bool
	noSave       bool
	autoPivot    int
	output       string
	timeoutSecs  int
	proxyURL     string
	tor          bool
	torAddress   string
	torSkipCheck bool
	userAgent    string
	uaMode       string
	doh          bool
	dohProvider  string
	yes           bool // skip OPSEC pre-flight prompt
	minConfidence float64
	allModules    []core.Module
	version       string
	buildDate     string
	compact      bool   // compact triage output (≤6 lines)
	field        bool   // single pipe-delimited line for scripting
	webhookURL   string // override PHONEACCESS_WEBHOOK_URL for one run
}

func NewRootCommand(version, buildDate string, registry []core.Module) *cobra.Command {
	opts := &options{
		format:      "terminal",
		timeoutSecs: 30,
		allModules:  registry,
		version:     version,
		buildDate:   buildDate,
	}

	cmd := &cobra.Command{
		Use:           "phoneaccess",
		Short:         "Offline phone number intelligence toolkit",
		Args:          cobra.ArbitraryArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			raw := args[0]
			if strings.HasPrefix(raw, "+") || looksLikeNumber(raw) {
				fmt.Fprintf(cmd.ErrOrStderr(), "Note: bare number syntax is deprecated. Use: phoneaccess investigate %s\n\n", raw)
				return opts.runInvestigation(cmd.Context(), cmd.OutOrStdout(), raw)
			}
			return cmd.Help()
		},
	}

	// Flags for the deprecated bare-number path (hidden so they don't clutter help).
	cmd.Flags().StringVar(&opts.format, "format", "terminal", "output format: terminal, json, csv, txt, or pdf")
	cmd.Flags().StringVarP(&opts.moduleNames, "modules", "m", "", "comma-separated list of modules to run")
	cmd.Flags().BoolVar(&opts.active, "active", false, "run active/probing modules")
	cmd.Flags().BoolVar(&opts.passive, "passive", false, "disable active network probing")
	cmd.Flags().BoolVar(&opts.noSave, "no-save", false, "skip database persistence")
	cmd.Flags().IntVar(&opts.autoPivot, "auto-pivot", 0, "maximum auto-pivot hop depth")
	cmd.Flags().StringVarP(&opts.output, "output", "o", "", "write output to file path")
	cmd.Flags().IntVar(&opts.timeoutSecs, "timeout", 30, "per-module timeout in seconds")
	cmd.Flags().StringVar(&opts.proxyURL, "proxy", "", "Proxy URL (e.g. socks5://127.0.0.1:9050, http://user:pass@host:port)")
	cmd.Flags().BoolVar(&opts.tor, "tor", false, "Route all requests through Tor (shorthand for --proxy socks5://127.0.0.1:9050)")
	cmd.Flags().StringVar(&opts.torAddress, "tor-address", "", "Custom Tor SOCKS5 address (default: 127.0.0.1:9050)")
	cmd.Flags().BoolVar(&opts.torSkipCheck, "tor-skip-check", false, "Skip Tor connectivity check")
	cmd.Flags().StringVar(&opts.userAgent, "user-agent", "", "Custom User-Agent string (sets --ua-mode=custom)")
	cmd.Flags().StringVar(&opts.uaMode, "ua-mode", "", "UA rotation mode: fixed (default), random, custom")

	if err := cmd.Flags().MarkHidden("format"); err == nil {
		_ = cmd.Flags().MarkHidden("modules")
		_ = cmd.Flags().MarkHidden("m")
		_ = cmd.Flags().MarkHidden("active")
		_ = cmd.Flags().MarkHidden("passive")
		_ = cmd.Flags().MarkHidden("no-save")
		_ = cmd.Flags().MarkHidden("auto-pivot")
		_ = cmd.Flags().MarkHidden("output")
		_ = cmd.Flags().MarkHidden("o")
		_ = cmd.Flags().MarkHidden("timeout")
		_ = cmd.Flags().MarkHidden("proxy")
		_ = cmd.Flags().MarkHidden("tor")
		_ = cmd.Flags().MarkHidden("tor-address")
		_ = cmd.Flags().MarkHidden("tor-skip-check")
		_ = cmd.Flags().MarkHidden("user-agent")
		_ = cmd.Flags().MarkHidden("ua-mode")
	}

	cmd.AddCommand(newInvestigateCommand(opts))
	cmd.AddCommand(newVersionCommand(version, buildDate))
	cmd.AddCommand(newModulesCommand(registry))
	cmd.AddCommand(newKeysCommand())
	cmd.AddCommand(newSetupCommand())
	cmd.AddCommand(newCasesCommand())
	cmd.AddCommand(newPivotCommand(opts))

	return cmd
}

func looksLikeNumber(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func newInvestigateCommand(o *options) *cobra.Command {
	// Local opts for the investigate subcommand — separate FlagSet from root.
	local := &options{
		format:      "terminal",
		timeoutSecs: 30,
		allModules:  o.allModules,
		version:     o.version,
		buildDate:   o.buildDate,
	}
	var batch bool

	cmd := &cobra.Command{
		Use:          "investigate <number|file|->",
		Short:        "Investigate a phone number",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if local.compact && local.field {
				return errors.New("--compact and --field are mutually exclusive")
			}
			arg := args[0]
			if batch {
				return local.runBatch(cmd.Context(), cmd.OutOrStdout(), arg, time.Now)
			}
			if arg == "-" {
				scanner := bufio.NewScanner(cmd.InOrStdin())
				if !scanner.Scan() {
					return errors.New("no input on stdin")
				}
				arg = strings.TrimSpace(scanner.Text())
				if arg == "" {
					return errors.New("empty phone number from stdin")
				}
			}
			return local.runInvestigation(cmd.Context(), cmd.OutOrStdout(), arg)
		},
	}

	cmd.Flags().StringVar(&local.format, "format", "terminal", "output format: terminal, json, csv, txt, pdf, gexf, jsonld, compact, field")
	cmd.Flags().StringVarP(&local.moduleNames, "modules", "m", "", "comma-separated list of modules to run")
	cmd.Flags().BoolVar(&local.active, "active", false, "run active/probing modules")
	cmd.Flags().BoolVar(&local.passive, "passive", false, "disable active network probing")
	cmd.Flags().BoolVar(&local.noSave, "no-save", false, "skip database persistence")
	cmd.Flags().IntVar(&local.autoPivot, "auto-pivot", 0, "maximum auto-pivot hop depth")
	cmd.Flags().StringVarP(&local.output, "output", "o", "", "write output to file path")
	cmd.Flags().IntVar(&local.timeoutSecs, "timeout", 30, "per-module timeout in seconds")
	cmd.Flags().BoolVar(&batch, "batch", false, "treat argument as a file of phone numbers")
	cmd.Flags().StringVar(&local.proxyURL, "proxy", "", "Proxy URL (e.g. socks5://127.0.0.1:9050, http://user:pass@host:port)")
	cmd.Flags().BoolVar(&local.tor, "tor", false, "Route all requests through Tor (shorthand for --proxy socks5://127.0.0.1:9050)")
	cmd.Flags().StringVar(&local.torAddress, "tor-address", "", "Custom Tor SOCKS5 address (default: 127.0.0.1:9050)")
	cmd.Flags().BoolVar(&local.torSkipCheck, "tor-skip-check", false, "Skip Tor connectivity check")
	cmd.Flags().StringVar(&local.userAgent, "user-agent", "", "Custom User-Agent string (sets --ua-mode=custom)")
	cmd.Flags().StringVar(&local.uaMode, "ua-mode", "", "UA rotation mode: fixed (default), random, custom")
	cmd.Flags().BoolVar(&local.doh, "doh", false, "Enable DNS-over-HTTPS to prevent DNS leaks")
	cmd.Flags().StringVar(&local.dohProvider, "doh-provider", "cloudflare", "DoH provider: cloudflare (default), google, quad9, or a custom URL")
	cmd.Flags().BoolVarP(&local.yes, "yes", "y", false, "Skip OPSEC pre-flight prompt (for non-interactive/scripted use)")
	cmd.Flags().Float64Var(&local.minConfidence, "min-confidence", 0, "hide terminal findings below this confidence (0 = show all; JSON always includes all)")
	cmd.Flags().BoolVar(&local.compact, "compact", false, "compact triage output (≤6 lines); alias for --format compact")
	cmd.Flags().BoolVar(&local.field, "field", false, "pipe-delimited single line for scripting; alias for --format field")
	cmd.Flags().StringVar(&local.webhookURL, "webhook", "", "webhook URL to notify after investigation (overrides PHONEACCESS_WEBHOOK_URL)")

	return cmd
}

func newSetupCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "setup",
		Short:        "Configure integrations",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
	}
	cmd.AddCommand(&cobra.Command{
		Use:          "whatsapp",
		Short:        "Link your WhatsApp account by QR",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := whatsapp.Setup(cmd.Context(), cmd.OutOrStdout()); err != nil {
				return err
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "WhatsApp session saved to ~/.phoneaccess/whatsapp_session.db")
			return err
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:          "telegram",
		Short:        "Authenticate Telegram with phone and OTP",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := telegram.Setup(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout()); err != nil {
				return err
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "Telegram session saved to ~/.phoneaccess/telegram_session.json")
			return err
		},
	})
	return cmd
}

func (o *options) runInvestigation(ctx context.Context, stdout io.Writer, raw string) error {
	format, err := o.resolveFormat()
	if err != nil {
		return err
	}
	if o.timeoutSecs <= 0 {
		return errors.New("timeout must be greater than 0 seconds")
	}

	number, err := core.NormalizePhoneNumber(raw)
	if err != nil {
		if core.IsInvalidPhoneNumber(err) {
			return fmt.Errorf("phone number is invalid: %w", err)
		}
		return fmt.Errorf("normalize phone number: %w", err)
	}

	selected, err := selectModules(o.allModules, o.moduleNames)
	if err != nil {
		return err
	}

	if err := resolveAndApplyProxy(ctx, o, stdout, selected); err != nil {
		return err
	}

	if o.doh {
		providerURL := core.ResolveDoHProviderURL(o.dohProvider)
		if err := core.ApplyDoH(providerURL); err != nil {
			return fmt.Errorf("apply DoH: %w", err)
		}
	}

	if hasActiveModulesSelected(o, selected) && !o.yes {
		if err := printOpsecWarning(stdout, buildOpsecState(o)); err != nil {
			return err
		}
		ok, err := promptOpsecContinue(stdout, os.Stdin)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("aborted by user")
		}
	}

	selectedNames := selectedModuleNames(o.moduleNames)
	identitySelected := identityRecordSelected(o.moduleNames)

	engine := core.NewEngine(
		selected,
		core.WithModuleTimeout(time.Duration(o.timeoutSecs)*time.Second),
		core.WithActive(o.active),
		core.WithSelectedModules(selectedNames),
		core.WithPassive(o.passive),
		core.WithIdentityRecordBuilder(defaultIdentityBuilder(o.passive, identitySelected)),
	)
	report, err := engine.Run(ctx, number)
	if err != nil {
		return err
	}

	var caseID int64
	if o.autoPivot > 0 {
		autoPivotResult, err := o.runAutoPivot(ctx, report)
		if err != nil {
			return err
		}
		if autoPivotResult != nil && autoPivotResult.Chain != nil {
			report.PivotChain = autoPivotResult.Chain
		}
		if !o.noSave {
			rootID, err := o.saveInvestigationToDB(report, stdout, storage.InvestigationLink{}, true)
			if err != nil {
				return err
			}
			caseID = rootID
			if autoPivotResult != nil {
				if err := o.saveLinkedInvestigations(rootID, autoPivotResult.Linked); err != nil {
					return err
				}
			}
		}
	} else if !o.noSave {
		id, err := o.saveInvestigationToDB(report, stdout, storage.InvestigationLink{}, true)
		if err != nil {
			return err
		}
		caseID = id
	}

	o.fireWebhook(ctx, report, caseID)
	return o.writeReport(report, format, stdout)
}

// fireWebhook delivers a webhook notification in a best-effort manner.
// Errors are logged as warnings to stdout but never fail the investigation.
func (o *options) fireWebhook(ctx context.Context, report *core.InvestigationReport, caseID int64) {
	store, _ := config.NewDefaultStore()
	webhookURL := o.webhookURL
	if webhookURL == "" {
		webhookURL = resolveConfig(store, "PHONEACCESS_WEBHOOK_URL")
	}
	if webhookURL == "" {
		return
	}
	secret := resolveConfig(store, "PHONEACCESS_WEBHOOK_SECRET")
	// When --webhook flag is set explicitly, deliver regardless of risk band.
	// The risk minimum only applies to config-driven webhook URLs.
	var riskMin core.RiskBand
	if o.webhookURL != "" {
		riskMin = core.RiskBandLow
	} else {
		riskMinStr := resolveConfig(store, "PHONEACCESS_WEBHOOK_RISK_MIN")
		riskMin = core.RiskBand(strings.ToUpper(strings.TrimSpace(riskMinStr)))
		switch riskMin {
		case core.RiskBandLow, core.RiskBandModerate, core.RiskBandHigh, core.RiskBandCritical:
			// valid
		default:
			riskMin = core.RiskBandHigh
		}
	}
	cfg := exporters.WebhookConfig{URL: webhookURL, Secret: secret, RiskMin: riskMin}
	if err := exporters.DeliverWebhook(ctx, cfg, report, caseID); err != nil {
		fmt.Fprintf(os.Stderr, "webhook warning: %v\n", err)
	}
}

func (o *options) resolveFormat() (string, error) {
	// Boolean shorthand flags take precedence over --format.
	if o.compact {
		return "compact", nil
	}
	if o.field {
		return "field", nil
	}

	format := strings.ToLower(strings.TrimSpace(o.format))
	if format == "" {
		format = "terminal"
	}

	// compact/field can also be set via --format compact / --format field.
	if format == "compact" || format == "field" {
		return format, nil
	}

	if o.output != "" {
		if ext := exporters.FormatFromPath(o.output); ext != "" {
			if !exporters.Supported(ext) {
				return "", fmt.Errorf("unsupported output extension %q; use .json, .csv, .pdf, .txt, .gexf, or .jsonld", "."+ext)
			}
			return ext, nil
		}
	}
	switch format {
	case "terminal", "json", "csv", "pdf", "txt", "text", "gexf", "jsonld":
		if format == "text" {
			return "txt", nil
		}
		return format, nil
	default:
		return "", fmt.Errorf("unsupported format %q; use terminal, json, csv, txt, pdf, gexf, jsonld, compact, or field", o.format)
	}
}

func (o *options) saveInvestigationToDB(report *core.InvestigationReport, stdout io.Writer, link storage.InvestigationLink, printMatches bool) (int64, error) {
	if report == nil {
		return 0, nil
	}
	s, err := storage.Open("")
	if err != nil {
		return 0, nil // Silently fail on storage error for now
	}
	defer s.Close()

	e164 := ""
	if report.Number != nil {
		e164 = cliFirstNonEmpty(report.Number.E164, report.Number.RawInput)
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		return 0, err
	}

	risk := report.RiskScore
	if risk == nil {
		risk = core.ScoreRisk(report)
	}

	var pivots []storage.Pivot
	if identity, ok := report.IdentityRecord.(*correlator.UnifiedIdentityRecord); ok {
		for _, claim := range identity.Claims {
			switch claim.Field {
			case correlator.FieldEmail, correlator.FieldUsername, correlator.FieldName:
				if strings.TrimSpace(claim.Value) != "" {
					pivots = append(pivots, storage.Pivot{
						Type:       claim.Field,
						Value:      claim.Value,
						Confidence: claim.Weight,
						Source:     claim.Source.Name,
					})
				}
			}
		}
	}

	id, matches, err := s.SaveInvestigation(e164, string(reportJSON), risk.Score, string(risk.Band), pivots, link)
	if err != nil {
		return 0, err
	}

	// Persist profile photo pHash for cross-session matching.
	if report.ImageIntelligence != nil && strings.TrimSpace(report.ImageIntelligence.PhotoPHash) != "" {
		_ = s.StorePhotoHash(id, e164,
			report.ImageIntelligence.PhotoSource,
			report.ImageIntelligence.PhotoPHash,
			report.ImageIntelligence.PhotoPath)
	}

	if printMatches && len(matches) > 0 && o.format == "terminal" {
		fmt.Fprintln(stdout, "\nPRIOR INVESTIGATIONS")
		for _, m := range matches {
			dateStr := m.Investigation.CreatedAt.Format("2006-01-02")
			fmt.Fprintf(stdout, "  %s %s also seen in case #%d (%s, %s)\n",
				strings.Title(m.PivotType), m.PivotValue, m.Investigation.ID, m.Investigation.PhoneE164, dateStr)
		}
	}
	return id, nil
}

func (o *options) saveLinkedInvestigations(parentID int64, linked []*core.LinkedInvestigation) error {
	for _, item := range linked {
		if item == nil || item.Report == nil {
			continue
		}
		link := storage.InvestigationLink{
			ParentID:   parentID,
			PivotType:  item.ParentType,
			PivotValue: item.ParentValue,
			Depth:      item.Depth,
		}
		childID, err := o.saveInvestigationToDB(item.Report, io.Discard, link, false)
		if err != nil {
			return err
		}
		if childID > 0 && len(item.Children) > 0 {
			if err := o.saveLinkedInvestigations(childID, item.Children); err != nil {
				return err
			}
		}
	}
	return nil
}

func (o *options) runAutoPivot(ctx context.Context, report *core.InvestigationReport) (*core.AutoPivotResult, error) {
	if report == nil || o.autoPivot <= 0 {
		return nil, nil
	}
	depth := o.autoPivot
	if depth > 3 {
		depth = 3
	}
	var searcher core.UsernameSearcher
	if !o.passive {
		client := core.NewHTTPClient(core.DefaultHTTPTimeout)
		services := enumerator.Services()
		limiter := core.NewRateLimiter(2 * time.Second)
		searcher = func(ctx context.Context, username string) ([]core.UsernameProfileHit, error) {
			hits, err := enumerator.SearchUsernameProfiles(ctx, client, services, username, limiter)
			if err != nil {
				return nil, err
			}
			out := make([]core.UsernameProfileHit, 0, len(hits))
			for _, hit := range hits {
				out = append(out, core.UsernameProfileHit{
					Platform:   hit.Platform,
					URL:        hit.URL,
					Source:     hit.Source,
					Confidence: hit.Confidence,
				})
			}
			return out, nil
		}
	}
	engine := core.NewAutoPivotEngine(
		core.WithAutoPivotDepth(depth),
		core.WithAutoPivotDelay(2*time.Second),
		core.WithAutoPivotUsernameSearcher(searcher),
	)
	return engine.Run(ctx, report)
}

func (o *options) writeReport(report *core.InvestigationReport, format string, stdout io.Writer) error {
	switch format {
	case "terminal":
		_, err := io.WriteString(stdout, NewTerminalRenderer(o.minConfidence).Render(report))
		return err
	case "compact":
		_, err := io.WriteString(stdout, NewCompactRenderer().Render(report))
		return err
	case "field":
		_, err := io.WriteString(stdout, NewFieldRenderer().Render(report))
		return err
	}

	if format == "pdf" && o.output == "" {
		_, err := io.WriteString(stdout, "PDF export requires an output file; use -o report.pdf\n")
		return err
	}

	var exporter exporters.Exporter
	var err error
	if format == "txt" {
		exporter = exporters.NewTextExporter(NewTerminalRenderer(o.minConfidence).Render)
	} else {
		exporter, err = exporters.New(format)
		if err != nil {
			return err
		}
	}

	if o.output == "" {
		return exporter.Export(report, stdout)
	}

	file, err := os.Create(o.output)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer file.Close()
	if err := exporter.Export(report, file); err != nil {
		return err
	}
	return nil
}

func newVersionCommand(version, buildDate string) *cobra.Command {
	return &cobra.Command{
		Use:          "version",
		Short:        "Print version",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "phoneaccess %s\nbuild date: %s\ngo version: %s\n", version, buildDate, runtime.Version())
			return err
		},
	}
}

func newModulesCommand(registry []core.Module) *cobra.Command {
	return &cobra.Command{
		Use:          "modules",
		Short:        "List registered modules",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if len(registry) == 0 {
				_, err := fmt.Fprintln(out, "No modules registered.")
				return err
			}
			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			if _, err := fmt.Fprintln(tw, "Name\tTier\tRequires Key\tDescription"); err != nil {
				return err
			}
			for _, module := range registry {
				apiKey := "no"
				if module.RequiresAPIKey() {
					apiKey = "yes"
				}
				if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", module.Name(), module.Tier(), apiKey, module.Description()); err != nil {
					return err
				}
			}
			return tw.Flush()
		},
	}
}

func (o *options) runBatch(ctx context.Context, stdout io.Writer, path string, now func() time.Time) error {
	if o.timeoutSecs <= 0 {
		return errors.New("timeout must be greater than 0 seconds")
	}
	numbers, err := readBatchNumbers(path)
	if err != nil {
		return err
	}
	if len(numbers) == 0 {
		return errors.New("batch file contains no phone numbers")
	}

	selected, err := selectModules(o.allModules, o.moduleNames)
	if err != nil {
		return err
	}

	if err := resolveAndApplyProxy(ctx, o, stdout, selected); err != nil {
		return err
	}

	if o.doh {
		providerURL := core.ResolveDoHProviderURL(o.dohProvider)
		if err := core.ApplyDoH(providerURL); err != nil {
			return fmt.Errorf("apply DoH: %w", err)
		}
	}

	if hasActiveModulesSelected(o, selected) && !o.yes {
		if err := printOpsecWarning(stdout, buildOpsecState(o)); err != nil {
			return err
		}
		ok, err := promptOpsecContinue(stdout, os.Stdin)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("aborted by user")
		}
	}

	selectedNames := selectedModuleNames(o.moduleNames)
	identitySelected := identityRecordSelected(o.moduleNames)

	compactMode := o.compact || strings.ToLower(strings.TrimSpace(o.format)) == "compact"
	fieldMode := o.field || strings.ToLower(strings.TrimSpace(o.format)) == "field"
	quietMode := compactMode || fieldMode // suppress progress/summary in triage modes

	reports := make([]*core.InvestigationReport, 0, len(numbers))
	for i, raw := range numbers {
		if !quietMode {
			if _, err := fmt.Fprintf(stdout, "[%d/%d] Investigating %s...\n", i+1, len(numbers), raw); err != nil {
				return err
			}
		}
		number, err := core.NormalizePhoneNumber(raw)
		if err != nil {
			if core.IsInvalidPhoneNumber(err) {
				return fmt.Errorf("phone number %q is invalid: %w", raw, err)
			}
			return fmt.Errorf("normalize phone number %q: %w", raw, err)
		}
		engine := core.NewEngine(
			selected,
			core.WithModuleTimeout(time.Duration(o.timeoutSecs)*time.Second),
			core.WithActive(o.active),
			core.WithSelectedModules(selectedNames),
			core.WithPassive(o.passive),
			core.WithIdentityRecordBuilder(defaultIdentityBuilder(o.passive, identitySelected)),
		)
		report, err := engine.Run(ctx, number)
		if err != nil {
			return fmt.Errorf("investigate %s: %w", raw, err)
		}
		reports = append(reports, report)

		// Per-investigation output in triage modes.
		if compactMode {
			if _, err := io.WriteString(stdout, NewCompactRenderer().Render(report)); err != nil {
				return err
			}
		} else if fieldMode {
			if _, err := io.WriteString(stdout, NewFieldRenderer().Render(report)); err != nil {
				return err
			}
		}

		// Fire webhook per investigation (best-effort, not blocking).
		o.fireWebhook(ctx, report, 0)
	}

	csvPath, jsonPath := batchOutputPaths(now())
	if err := writeBatchCSV(csvPath, reports); err != nil {
		return err
	}
	if err := writeBatchJSON(jsonPath, reports); err != nil {
		return err
	}

	if quietMode {
		return nil
	}

	if _, err := fmt.Fprintf(stdout, "\nWrote %s and %s\n\n", csvPath, jsonPath); err != nil {
		return err
	}
	return writeBatchSummary(stdout, reports)
}

func readBatchNumbers(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open batch file: %w", err)
	}
	defer file.Close()

	var numbers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		numbers = append(numbers, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read batch file: %w", err)
	}
	return numbers, nil
}

func batchOutputPaths(t time.Time) (string, string) {
	stamp := t.UTC().Format("20060102_150405")
	return fmt.Sprintf("phoneaccess_batch_%s.csv", stamp), fmt.Sprintf("phoneaccess_batch_%s.json", stamp)
}

func writeBatchCSV(path string, reports []*core.InvestigationReport) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create batch csv: %w", err)
	}
	defer file.Close()

	exporter := exporters.NewCSVExporter()
	for i, report := range reports {
		if err := exporter.ExportAppend(report, file, i > 0); err != nil {
			return err
		}
	}
	return nil
}

func writeBatchJSON(path string, reports []*core.InvestigationReport) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create batch json: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(reports)
}

func writeBatchSummary(w io.Writer, reports []*core.InvestigationReport) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "number\trisk band\tspam score\tbreach count\tname hint"); err != nil {
		return err
	}
	for _, report := range reports {
		number := ""
		if report.Number != nil {
			number = cliFirstNonEmpty(report.Number.E164, report.Number.RawInput)
		}
		risk := report.RiskScore
		if risk == nil {
			risk = core.ScoreRisk(report)
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			number,
			risk.Band,
			cliFirstNonEmpty(cliFinding(report, "spam", "spam_score"), "0"),
			cliFirstNonEmpty(cliFinding(report, "breach", "breach_count"), "0"),
			cliFirstNonEmpty(cliFinding(report, "reverse", "name_hint"), "unknown"),
		); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func newKeysCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "keys",
		Short:        "Manage local API keys",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
	}

	cmd.AddCommand(&cobra.Command{
		Use:          "list",
		Short:        "List configured key names",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := config.NewDefaultStore()
			if err != nil {
				return err
			}
			configured, err := store.ListKeys()
			if err != nil {
				return err
			}
			configuredSet := map[string]bool{}
			for _, key := range configured {
				configuredSet[key] = true
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			if _, err := fmt.Fprintln(tw, "Key\tConfigured\tDescription"); err != nil {
				return err
			}
			for _, item := range apiKeyCatalog() {
				status := "no"
				if configuredSet[item.Name] {
					status = "yes"
				}
				if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\n", item.Name, status, item.Description); err != nil {
					return err
				}
			}
			return tw.Flush()
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:          "set <key> <value>",
		Short:        "Set an API key",
		Args:         cobra.ExactArgs(2),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := config.NewDefaultStore()
			if err != nil {
				return err
			}
			if err := store.SetKey(args[0], args[1]); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Saved %s\n", args[0])
			return err
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:          "unset <key>",
		Short:        "Unset an API key",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := config.NewDefaultStore()
			if err != nil {
				return err
			}
			if err := store.UnsetKey(args[0]); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Removed %s\n", args[0])
			return err
		},
	})

	return cmd
}

func selectModules(registry []core.Module, csv string) ([]core.Module, error) {
	if strings.TrimSpace(csv) == "" {
		return registry, nil
	}

	byName := make(map[string]core.Module, len(registry))
	names := make([]string, 0, len(registry))
	for _, module := range registry {
		byName[module.Name()] = module
		names = append(names, module.Name())
	}
	sort.Strings(names)

	selectedNames := map[string]bool{}
	for _, rawName := range strings.Split(csv, ",") {
		name := strings.TrimSpace(rawName)
		if name == "" {
			continue
		}
		if isIdentityModuleName(name) {
			selectedNames["correlator"] = true
			continue
		}
		if _, ok := byName[name]; !ok {
			return nil, fmt.Errorf("unknown module %q; available modules: %s", name, strings.Join(names, ", "))
		}
		selectedNames[name] = true
	}

	selected := make([]core.Module, 0, len(registry))
	for _, module := range registry {
		if selectedNames[module.Name()] {
			selected = append(selected, module)
			continue
		}
		selected = append(selected, skippedModule{name: module.Name(), description: module.Description()})
	}
	return selected, nil
}

func selectedModuleNames(csv string) map[string]bool {
	selected := map[string]bool{}
	if strings.TrimSpace(csv) == "" {
		return selected
	}
	for _, rawName := range strings.Split(csv, ",") {
		name := strings.TrimSpace(rawName)
		if name == "" {
			continue
		}
		if isIdentityModuleName(name) {
			continue
		}
		selected[name] = true
	}
	return selected
}

func identityRecordSelected(csv string) bool {
	if strings.TrimSpace(csv) == "" {
		return true
	}
	for _, rawName := range strings.Split(csv, ",") {
		if isIdentityModuleName(strings.TrimSpace(rawName)) {
			return true
		}
	}
	return false
}

func isIdentityModuleName(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "correlator", "identity", "identity_record", "identity-record":
		return true
	default:
		return false
	}
}

type skippedModule struct {
	name        string
	description string
}

func (m skippedModule) Name() string {
	return m.name
}

func (m skippedModule) Description() string {
	return m.description
}

func (m skippedModule) RequiresAPIKey() bool {
	return false
}

func (m skippedModule) Tier() core.ModuleTier {
	return core.TierPassive
}

func (m skippedModule) DryRun(ctx context.Context, number *core.PhoneNumber) error {
	return nil
}

func (m skippedModule) Run(ctx context.Context, number *core.PhoneNumber) (*core.ModuleResult, error) {
	return &core.ModuleResult{
		ModuleName: m.name,
		Status:     core.ModuleStatusSkipped,
		Findings: map[string]string{
			"skipped": "true",
			"reason":  "not selected by --modules",
		},
		Evidence: []string{"Module skipped because it was not selected by --modules."},
	}, nil
}

func moduleKeyNames(moduleName string) string {
	switch moduleName {
	case "carrier":
		return "NUMVERIFY_API_KEY, ABSTRACT_API_KEY, TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_ENABLE_CALLER_NAME"
	case "voip":
		return "IPQS_API_KEY, ABSTRACT_API_KEY"
	case "search":
		return "GOOGLE_CSE_API_KEY, GOOGLE_CSE_CX, BING_SEARCH_API_KEY"
	case "paste":
		return "GITHUB_TOKEN, INTELX_API_KEY, DEHASHED_EMAIL, DEHASHED_API_KEY"
	case "truecaller":
		return "TRUECALLER_INSTALLATION_ID"
	case "reverse":
		return "OPENCNAM_SID, TRESTLE_API_KEY"
	case "telegram":
		return "TELEGRAM_APP_ID, TELEGRAM_APP_HASH"
	case "intelligence":
		return "OPENSANCTIONS_API_KEY"
	default:
		return "-"
	}
}

type apiKeyInfo struct {
	Name        string
	Description string
}

func apiKeyCatalog() []apiKeyInfo {
	return []apiKeyInfo{
		{Name: "NUMVERIFY_API_KEY", Description: "NumVerify / APILayer carrier lookup, plan-based pricing, numverify.com"},
		{Name: "VERIPHONE_API_KEY", Description: "Veriphone carrier lookup, 1,000 free/month, signup/docs: https://veriphone.io/docs"},
		{Name: "ABSTRACT_API_KEY", Description: "AbstractAPI phone validation, 250 free/month, signup: https://www.abstractapi.com/phone-validator"},
		{Name: "IPQS_API_KEY", Description: "IPQualityScore phone validation, plan-based pricing, ipqualityscore.com"},
		{Name: "OPENCNAM_SID", Description: "OpenCNAM reverse lookup, plan-based pricing, opencnam.com"},
		{Name: "NUMLOOKUP_API_KEY", Description: "NumLookup phone intelligence, 500 free/month, numlookupapi.com"},
		{Name: "LEAKSIGHT_API_KEY", Description: "LeakSight breach enrichment, plan-based pricing, leaksight.com"},
		{Name: "TRESTLE_API_KEY", Description: "Trestle IQ reverse lookup, paid/partner access, trestleiq.com"},
		{Name: "HIBP_API_KEY", Description: "Have I Been Pwned breach intelligence API key ($3.50/month — haveibeenpwned.com/API/Key); most recognised breach database"},
		{Name: "SNUSBASE_API_KEY", Description: "Snusbase breach intelligence API key"},
		{Name: "BREACHDIRECTORY_API_KEY", Description: "BreachDirectory API key via RapidAPI"},
		{Name: "LEAKLOOKUP_API_KEY", Description: "Leak-Lookup API key"},
		{Name: "GOOGLE_CSE_API_KEY", Description: "Google Custom Search API key for targeted web dork searches"},
		{Name: "GOOGLE_CSE_CX", Description: "Google Custom Search Engine context identifier"},
		{Name: "BING_SEARCH_API_KEY", Description: "Bing Web Search API key for targeted dork searches"},
		{Name: "OPENCORPORATES_API_KEY", Description: "OpenCorporates officer search API key, free tier available at opencorporates.com/api_accounts/new"},
		{Name: "PACER_USERNAME", Description: "PACER username for federal court party search"},
		{Name: "PACER_PASSWORD", Description: "PACER password for federal court party search"},
		{Name: "GITHUB_TOKEN", Description: "GitHub token for code search rate limits and better coverage"},
		{Name: "INTELX_API_KEY", Description: "IntelX phonebook search API key, free signup at intelx.io"},
		{Name: "DEHASHED_EMAIL", Description: "DeHashed account email for Basic Auth"},
		{Name: "DEHASHED_API_KEY", Description: "DeHashed API key for breach enrichment"},
		{Name: "TWILIO_ACCOUNT_SID", Description: "Twilio Lookup v2 carrier lookup, pay-per-use, signup: https://www.twilio.com/en-us/go/try-twilio-de-1"},
		{Name: "TWILIO_AUTH_TOKEN", Description: "Twilio Lookup v2 carrier lookup, pay-per-use, signup: https://www.twilio.com/en-us/go/try-twilio-de-1"},
		{Name: "TWILIO_ENABLE_CALLER_NAME", Description: "Set to true to enable US caller name (additional cost per lookup)"},
		{Name: "TRUECALLER_INSTALLATION_ID", Description: "Truecaller unofficial session token; unsupported and operator-responsible, install/app: https://www.truecaller.com/download"},
		{Name: "TELEGRAM_APP_ID", Description: "Telegram MTProto app ID from https://my.telegram.org/apps — required for Telegram account discovery"},
		{Name: "TELEGRAM_APP_HASH", Description: "Telegram MTProto app hash from https://my.telegram.org/apps — required for Telegram account discovery"},
		{Name: "PROXY_URL", Description: "Proxy URL for all requests (e.g. socks5://127.0.0.1:9050, http://user:pass@host:port) — equivalent to --proxy flag"},
		{Name: "TOR_ENABLED", Description: "Set to true to route all requests through Tor (127.0.0.1:9050) — equivalent to --tor flag"},
		{Name: "TOR_ADDRESS", Description: "Custom Tor SOCKS5 address (default: 127.0.0.1:9050) — equivalent to --tor-address flag"},
		{Name: "VIRUSTOTAL_API_KEY", Description: "VirusTotal API key for phone-number threat intelligence cross-reference (free tier: 500 req/day — virustotal.com)"},
		{Name: "OPENSANCTIONS_API_KEY", Description: "OpenSanctions API key for higher-rate-limit access to the match endpoint (10,000 req/month free — opensanctions.org/api). Search endpoint always runs without a key."},
		{Name: "PHONEACCESS_FINANCE_VENMO", Description: "Set to 'allow' to enable Venmo phone-to-name resolution (opt-in, 50-lookup cap, 6 s inter-request delay)"},
		{Name: "PHONEACCESS_USER_AGENT", Description: "Custom User-Agent string used when --ua-mode=custom (or when --user-agent flag is set)"},
		{Name: "PHONEACCESS_UA_MODE", Description: "UA rotation mode: fixed (default, one consistent UA per run), random (new UA per request), custom (use PHONEACCESS_USER_AGENT)"},
		{Name: "SESSION_KEY_SOURCE", Description: "Session file encryption key source: machine (default, transparent), passphrase (PBKDF2 from user passphrase), both (PBKDF2 from passphrase + machine ID)"},
		{Name: "PHONEACCESS_DOH_ENABLED", Description: "Set to true to enable DNS-over-HTTPS on every run (equivalent to --doh flag)"},
		{Name: "PHONEACCESS_DOH_PROVIDER", Description: "DoH provider: cloudflare (default), google, quad9, or a custom URL (equivalent to --doh-provider flag)"},
		{Name: "TINEYE_API_KEY", Description: "TinEye reverse image search API key, 100 searches/month free — tineye.com/api"},
		{Name: "PHASH_HAMMING_THRESHOLD", Description: "Maximum Hamming distance for cross-session pHash match (default: 10; lower = stricter)"},
		{Name: "PHONEACCESS_MIN_CONFIDENCE", Description: "Default minimum confidence threshold for terminal display (0.0–1.0); findings below this are hidden from terminal but always present in JSON"},
		{Name: "PHONEACCESS_COMPACT", Description: "Set to true to use compact triage output (≤6 lines) as the persistent default (equivalent to --compact flag)"},
		{Name: "PHONEACCESS_WEBHOOK_URL", Description: "Webhook endpoint URL; supports generic HTTP, Slack incoming webhooks, and Discord (discord.com/api/webhooks — auto-detected)"},
		{Name: "PHONEACCESS_WEBHOOK_SECRET", Description: "HMAC-SHA256 signing secret for webhook payloads; if set, adds X-PhoneAccess-Signature header so the receiver can verify authenticity"},
		{Name: "PHONEACCESS_WEBHOOK_RISK_MIN", Description: "Minimum risk band to trigger webhook notification: LOW, MODERATE, HIGH, or CRITICAL (default: HIGH)"},
	}
}

func defaultIdentityBuilder(passive, selected bool) core.IdentityRecordBuilder {
	return func(ctx context.Context, report *core.InvestigationReport) any {
		e164 := ""
		if report != nil && report.Number != nil {
			e164 = report.Number.E164
		}
		if !selected {
			return &correlator.UnifiedIdentityRecord{
				Status:       correlator.StatusSkipped,
				Jurisdiction: correlator.JurisdictionForE164(e164),
				GeneratedAt:  time.Now().UTC(),
				Names:        []correlator.FieldCandidate{},
				Addresses:    []correlator.FieldCandidate{},
				DOBs:         []correlator.FieldCandidate{},
				Emails:       []correlator.FieldCandidate{},
				SocialLinks:  []correlator.FieldCandidate{},
				Conflicts:    []correlator.Conflict{},
				SourceRuns:   []correlator.SourceRun{},
				Note:         "identity correlation not selected by --modules",
			}
		}
		ctx = sources.ContextWithResponseCache(ctx, core.ResponseCacheFromContext(ctx))
		engine := correlator.NewEngine(defaultIdentitySources(), correlator.WithPassive(passive))
		record, err := engine.Run(ctx, e164)
		if err != nil {
			return &correlator.UnifiedIdentityRecord{
				Status:       correlator.StatusSkipped,
				Jurisdiction: correlator.JurisdictionForE164(e164),
				GeneratedAt:  time.Now().UTC(),
				Names:        []correlator.FieldCandidate{},
				Addresses:    []correlator.FieldCandidate{},
				DOBs:         []correlator.FieldCandidate{},
				Emails:       []correlator.FieldCandidate{},
				SocialLinks:  []correlator.FieldCandidate{},
				Conflicts:    []correlator.Conflict{},
				SourceRuns:   []correlator.SourceRun{},
				Note:         err.Error(),
			}
		}
		addMessengerIdentityClaims(record, report)
		addTruecallerIdentityRecord(record, report)
		addBreachIdentityClaims(record, report)
		addPublicRecordsIdentityClaims(record, report)
		return record
	}
}

func addMessengerIdentityClaims(record *correlator.UnifiedIdentityRecord, report *core.InvestigationReport) {
	if record == nil || report == nil || report.Messenger == nil {
		return
	}
	add := func(sourceName string, account *core.MessengerAccount) {
		if account == nil || !account.Found || strings.TrimSpace(account.DisplayName) == "" {
			return
		}
		now := time.Now().UTC()
		e164 := ""
		if report.Number != nil {
			e164 = cliFirstNonEmpty(report.Number.E164, report.Number.RawInput)
		}
		meta := correlator.SourceMeta{
			Name:          sourceName,
			Tier:          string(sources.TierCommercial),
			TierWeight:    sources.TierWeight(sources.TierCommercial),
			Jurisdictions: []string{correlator.JurisdictionForE164(e164)},
		}
		claim := correlator.PIIClaim{
			Field:     correlator.FieldName,
			Value:     account.DisplayName,
			Source:    meta,
			Weight:    meta.TierWeight,
			FetchedAt: now,
			Metadata: map[string]string{
				"profile_photo_path":  account.ProfilePhotoPath,
				"profile_photo_phash": account.ProfilePhotoPHash,
			},
		}
		record.Claims = append(record.Claims, claim)
		record.Names = append(record.Names, correlator.FieldCandidate{
			Field:           correlator.FieldName,
			NormalizedValue: correlator.NormalizeName(account.DisplayName),
			DisplayValue:    account.DisplayName,
			RawVariants:     []string{account.DisplayName},
			Sources:         []correlator.SourceMeta{meta},
			Confidence:      meta.TierWeight,
			ConfidenceLabel: correlator.ConfidenceLabel(meta.TierWeight),
			LastSeen:        now,
		})
		if meta.TierWeight > record.OverallConfidence {
			record.OverallConfidence = meta.TierWeight
		}
	}
	add("Telegram", report.Messenger.Telegram)
	add("WhatsApp", report.Messenger.WhatsApp)
	add("Signal", report.Messenger.Signal)
}

func addTruecallerIdentityRecord(record *correlator.UnifiedIdentityRecord, report *core.InvestigationReport) {
	if record == nil || report == nil {
		return
	}
	for _, result := range report.Results {
		if result == nil || !strings.EqualFold(result.ModuleName, "truecaller") || result.Data == nil {
			continue
		}
		data, err := json.Marshal(result.Data)
		if err != nil {
			return
		}
		var tc correlator.TruecallerRecord
		if err := json.Unmarshal(data, &tc); err != nil {
			return
		}
		if tc.Name == "" && tc.City == "" && len(tc.Emails) == 0 {
			return
		}
		record.Truecaller = &tc
		return
	}
}

func addBreachIdentityClaims(record *correlator.UnifiedIdentityRecord, report *core.InvestigationReport) {
	if record == nil || report == nil {
		return
	}
	for _, result := range report.Results {
		if result == nil || !strings.EqualFold(result.ModuleName, "breach") || result.Data == nil {
			continue
		}

		data, err := json.Marshal(result.Data)
		if err != nil {
			continue
		}
		var bResult struct {
			Breaches []struct {
				Emails    []string `json:"emails"`
				Usernames []string `json:"usernames"`
			} `json:"breaches"`
		}
		if err := json.Unmarshal(data, &bResult); err != nil {
			continue
		}

		now := time.Now().UTC()
		e164 := ""
		if report.Number != nil {
			e164 = cliFirstNonEmpty(report.Number.E164, report.Number.RawInput)
		}
		meta := correlator.SourceMeta{
			Name:          "Breach Intelligence",
			Tier:          "Breach",
			TierWeight:    0.25,
			Jurisdictions: []string{correlator.JurisdictionForE164(e164)},
		}

		for _, b := range bResult.Breaches {
			for _, email := range b.Emails {
				if strings.TrimSpace(email) == "" {
					continue
				}
				record.Claims = append(record.Claims, correlator.PIIClaim{
					Field:     correlator.FieldEmail,
					Value:     email,
					Source:    meta,
					Weight:    0.25,
					FetchedAt: now,
				})
			}
			for _, username := range b.Usernames {
				if strings.TrimSpace(username) == "" {
					continue
				}
				record.Claims = append(record.Claims, correlator.PIIClaim{
					Field:     correlator.FieldUsername,
					Value:     username,
					Source:    meta,
					Weight:    0.25,
					FetchedAt: now,
				})
			}
		}
	}
}

func addPublicRecordsIdentityClaims(record *correlator.UnifiedIdentityRecord, report *core.InvestigationReport) {
	if record == nil || report == nil {
		return
	}
	for _, result := range report.Results {
		if result == nil || !strings.EqualFold(result.ModuleName, "public_records") || result.Data == nil {
			continue
		}

		data, err := json.Marshal(result.Data)
		if err != nil {
			continue
		}
		var pr publicrecords.PublicRecordsResult
		if err := json.Unmarshal(data, &pr); err != nil {
			continue
		}

		now := time.Now().UTC()
		e164 := ""
		if report.Number != nil {
			e164 = cliFirstNonEmpty(report.Number.E164, report.Number.RawInput)
		}
		jurisdiction := correlator.JurisdictionForE164(e164)

		appendClaims := func(sourceName string, tier string, weight float64, values ...string) {
			meta := correlator.SourceMeta{
				Name:          sourceName,
				Tier:          tier,
				TierWeight:    weight,
				Jurisdictions: []string{jurisdiction},
			}
			for _, value := range values {
				value = strings.TrimSpace(value)
				if value == "" {
					continue
				}
				record.Claims = append(record.Claims, correlator.PIIClaim{
					Field:     correlator.FieldName,
					Value:     value,
					Source:    meta,
					Weight:    weight,
					FetchedAt: now,
				})
			}
		}

		for _, hit := range pr.EdgarHits {
			appendClaims("SEC EDGAR", "Commercial", 0.75, hit.EntityName)
		}
		for _, hit := range pr.OpencorpHits {
			appendClaims("OpenCorporates", "Government", 0.90, hit.OfficerName, hit.Company)
		}
		for _, hit := range pr.CompaniesHouseHits {
			appendClaims("Companies House", "Government", 0.90, hit.OfficerName, hit.CompanyName)
		}
		for _, hit := range pr.PacerHits {
			appendClaims("PACER", "Government", 0.90, hit.PartyName)
		}
		for _, hit := range pr.LicenseHits {
			appendClaims("Licenses", "Government", 0.90, hit.Name)
		}
	}
}

func defaultIdentitySources() []correlator.ClaimSource {
	return []correlator.ClaimSource{
		opencnam.New(),
		numlookup.New(),
		trestle.New(),
		leaksight.New(),
		ipqs.New(),
		companieshouse.New(),
		veriphone.New(),
		abstractapi.New(),
		twilio.New(),
		callerkit.New(),
		neutrino.New(),
		nigeriaphonebook.New(),
		paginebianche.New(),
		telelistas.New(),
		paginasblancasar.New(),
		dastelefon.New(),
	}
}

func cliFinding(report *core.InvestigationReport, moduleName, key string) string {
	for _, result := range report.Results {
		if result != nil && result.ModuleName == moduleName && result.Findings != nil {
			return strings.TrimSpace(result.Findings[key])
		}
	}
	return ""
}

func cliFirstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (m skippedModule) ProxyAware() bool { return true }

func resolveConfig(store *config.Store, key string) string {
	if store != nil {
		if cfg, err := store.Load(); err == nil {
			if val, ok := cfg.APIKeys[key]; ok && val != "" {
				return val
			}
		}
	}
	return os.Getenv(key)
}

func resolveAndInitUA(opts *options, store *config.Store) {
	uaMode := opts.uaMode
	customUA := opts.userAgent

	// --user-agent flag implies custom mode.
	if customUA != "" && uaMode == "" {
		uaMode = string(core.UAModeCustom)
	}

	// Fall back to config keys when flags are empty.
	if customUA == "" {
		customUA = resolveConfig(store, "PHONEACCESS_USER_AGENT")
	}
	if uaMode == "" {
		uaMode = resolveConfig(store, "PHONEACCESS_UA_MODE")
	}

	// --user-agent flag always wins over config key.
	if opts.userAgent != "" {
		customUA = opts.userAgent
		uaMode = string(core.UAModeCustom)
	}

	var mode core.UAMode
	switch core.UAMode(uaMode) {
	case core.UAModeRandom:
		mode = core.UAModeRandom
	case core.UAModeCustom:
		mode = core.UAModeCustom
	default:
		mode = core.UAModeFixed
	}

	core.InitGlobalPool(mode, customUA)
}

func resolveMinConfidenceConfig(opts *options, store *config.Store) {
	if opts.minConfidence > 0 {
		return // flag takes precedence
	}
	if val := resolveConfig(store, "PHONEACCESS_MIN_CONFIDENCE"); val != "" {
		if f, err := strconv.ParseFloat(val, 64); err == nil && f > 0 {
			opts.minConfidence = f
		}
	}
}

func resolveDoHConfig(opts *options, store *config.Store) {
	if !opts.doh {
		if strings.ToLower(resolveConfig(store, "PHONEACCESS_DOH_ENABLED")) == "true" {
			opts.doh = true
		}
	}
	if opts.dohProvider == "" || opts.dohProvider == "cloudflare" {
		if p := resolveConfig(store, "PHONEACCESS_DOH_PROVIDER"); p != "" {
			opts.dohProvider = p
		}
	}
}

func resolveCompactModeConfig(opts *options, store *config.Store) {
	if opts.compact || opts.field {
		return // flag takes precedence
	}
	if strings.ToLower(resolveConfig(store, "PHONEACCESS_COMPACT")) == "true" {
		opts.compact = true
	}
}

func resolveAndApplyProxy(ctx context.Context, opts *options, stdout io.Writer, registry []core.Module) error {
	store, _ := config.NewDefaultStore()
	resolveAndInitUA(opts, store)
	resolveDoHConfig(opts, store)
	resolveMinConfidenceConfig(opts, store)
	resolveCompactModeConfig(opts, store)
	
	proxyURLStr := opts.proxyURL
	if proxyURLStr == "" {
		proxyURLStr = resolveConfig(store, "PROXY_URL")
	}

	torEnabled := opts.tor
	if !torEnabled {
		if strings.ToLower(resolveConfig(store, "TOR_ENABLED")) == "true" {
			torEnabled = true
		}
	}

	torAddress := opts.torAddress
	if torAddress == "" {
		torAddress = resolveConfig(store, "TOR_ADDRESS")
	}

	cfg := core.ProxyConfig{}
	if torEnabled {
		cfg.Enabled = true
		cfg.Type = "tor"
		cfg.Address = torAddress
	} else if proxyURLStr != "" {
		cfg.Enabled = true
		u, err := url.Parse(proxyURLStr)
		if err == nil {
			cfg.Type = u.Scheme
			cfg.Address = u.Host
			if u.User != nil {
				cfg.Username = u.User.Username()
				cfg.Password, _ = u.User.Password()
			}
		} else {
			cfg.Type = "http"
			cfg.Address = proxyURLStr
		}
	}

	if cfg.Enabled {
		if err := core.ApplyGlobalProxy(cfg); err != nil {
			return fmt.Errorf("failed to apply proxy config: %w", err)
		}

		// Pre-flight check: verify the proxy is reachable
		if !(cfg.Type == "tor" && opts.torSkipCheck) {
			proxyHost := cfg.Address
			if cfg.Type == "tor" && proxyHost == "" {
				proxyHost = "127.0.0.1:9050"
			}
			if cfg.Type == "http" {
				if u, err := url.Parse(proxyURLStr); err == nil {
					proxyHost = u.Host
				}
			}
			conn, err := net.DialTimeout("tcp", proxyHost, 5*time.Second)
			if err != nil {
				if cfg.Type == "tor" {
					fmt.Fprintln(stdout, "\033[31m✗ Tor not detected. Is Tor running?\033[0m")
					return errors.New("tor check failed: connection refused")
				}
				return fmt.Errorf("proxy connection failed: %w", err)
			}
			conn.Close()
		}

		if cfg.Type == "tor" && !opts.torSkipCheck {
			fmt.Fprint(stdout, "Checking Tor connectivity... ")
			client := core.NewHTTPClient(10 * time.Second)
			req, _ := http.NewRequestWithContext(ctx, "GET", "https://check.torproject.org/api/ip", nil)
			resp, err := client.Do(req)
			if err != nil {
				fmt.Fprintln(stdout, "\033[31m✗ Tor not detected. Is Tor running?\033[0m")
				return fmt.Errorf("tor check failed: %w", err)
			}
			defer resp.Body.Close()
			var result struct { IsTor bool `json:"IsTor"` }
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || !result.IsTor {
				fmt.Fprintln(stdout, "\033[31m✗ Tor not detected. Is Tor running?\033[0m")
				return errors.New("tor check failed: not tor")
			}
			fmt.Fprintln(stdout, "\033[32m✓ Tor circuit established\033[0m")
		}

		for _, m := range registry {
			if !m.ProxyAware() {
				fmt.Fprintf(stdout, "⚠ %s module does not route through proxy — direct connection will be used.\n", m.Name())
			}
		}
	}
	return nil
}
