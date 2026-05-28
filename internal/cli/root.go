package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
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
	format      string
	moduleNames string
	passive     bool
	active      bool
	noSave      bool
	autoPivot   int
	output      string
	timeoutSecs int
	allModules  []core.Module
	version     string
	buildDate   string
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
		Use:           "phoneaccess <number>",
		Short:         "Offline phone number intelligence toolkit",
		Args:          cobra.ExactArgs(1),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.runInvestigation(cmd.Context(), cmd.OutOrStdout(), args[0])
		},
	}

	cmd.Flags().StringVar(&opts.format, "format", "terminal", "output format: terminal, json, csv, txt, or pdf")
	cmd.Flags().StringVar(&opts.moduleNames, "modules", "", "comma-separated list of modules to run")
	cmd.Flags().BoolVar(&opts.active, "active", false, "run active/probing modules")
	cmd.Flags().BoolVar(&opts.passive, "passive", false, "disable active network probing")
	cmd.Flags().BoolVar(&opts.noSave, "no-save", false, "skip database persistence")
	cmd.Flags().IntVar(&opts.autoPivot, "auto-pivot", 0, "maximum auto-pivot hop depth")
	cmd.Flags().StringVarP(&opts.output, "output", "o", "", "write output to file path")
	cmd.Flags().IntVar(&opts.timeoutSecs, "timeout", 30, "per-module timeout in seconds")

	cmd.AddCommand(newVersionCommand(version, buildDate))
	cmd.AddCommand(newModulesCommand(registry))
	cmd.AddCommand(newKeysCommand())
	cmd.AddCommand(newBatchCommand(opts))
	cmd.AddCommand(newWhatsAppCommand())
	cmd.AddCommand(newTelegramCommand())
	cmd.AddCommand(newCasesCommand())

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
			if autoPivotResult != nil {
				if err := o.saveLinkedInvestigations(rootID, autoPivotResult.Linked); err != nil {
					return err
				}
			}
		}
	} else if !o.noSave {
		if _, err := o.saveInvestigationToDB(report, stdout, storage.InvestigationLink{}, true); err != nil {
			return err
		}
	}

	return o.writeReport(report, format, stdout)
}

func (o *options) resolveFormat() (string, error) {
	format := strings.ToLower(strings.TrimSpace(o.format))
	if format == "" {
		format = "terminal"
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
		return "", fmt.Errorf("unsupported format %q; use terminal, json, csv, txt, pdf, gexf, or jsonld", o.format)
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
	if format == "terminal" {
		_, err := io.WriteString(stdout, NewTerminalRenderer().Render(report))
		return err
	}
	if format == "pdf" && o.output == "" {
		_, err := io.WriteString(stdout, "PDF export requires an output file; use -o report.pdf\n")
		return err
	}

	var exporter exporters.Exporter
	var err error
	if format == "txt" {
		exporter = exporters.NewTextExporter(NewTerminalRenderer().Render)
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

func newBatchCommand(o *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:          "batch <file>",
		Short:        "Investigate phone numbers from a text file",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.runBatch(cmd.Context(), cmd.OutOrStdout(), args[0], time.Now)
		},
	}
	cmd.Flags().StringVar(&o.moduleNames, "modules", "", "comma-separated list of modules to run")
	cmd.Flags().BoolVar(&o.active, "active", false, "run active/probing modules")
	cmd.Flags().BoolVar(&o.passive, "passive", false, "disable active network probing")
	cmd.Flags().IntVar(&o.timeoutSecs, "timeout", 30, "per-module timeout in seconds")
	return cmd
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
	selectedNames := selectedModuleNames(o.moduleNames)
	identitySelected := identityRecordSelected(o.moduleNames)

	reports := make([]*core.InvestigationReport, 0, len(numbers))
	for i, raw := range numbers {
		if _, err := fmt.Fprintf(stdout, "[%d/%d] Investigating %s...\n", i+1, len(numbers), raw); err != nil {
			return err
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
	}

	csvPath, jsonPath := batchOutputPaths(now())
	if err := writeBatchCSV(csvPath, reports); err != nil {
		return err
	}
	if err := writeBatchJSON(jsonPath, reports); err != nil {
		return err
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

func newWhatsAppCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "whatsapp",
		Short:        "Manage WhatsApp session",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
	}
	cmd.AddCommand(&cobra.Command{
		Use:          "setup",
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
	return cmd
}

func newTelegramCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "telegram",
		Short:        "Manage Telegram session",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
	}
	cmd.AddCommand(&cobra.Command{
		Use:          "setup",
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
		{Name: "PHONEACCESS_FINANCE_VENMO", Description: "Set to 'allow' to enable Venmo phone-to-name resolution (opt-in, 50-lookup cap, 6 s inter-request delay)"},
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
