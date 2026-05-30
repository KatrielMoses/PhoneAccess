package core

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

const DefaultModuleTimeout = 30 * time.Second

type Engine struct {
	modules         []Module
	timeout         time.Duration
	passive         bool
	active          bool
	explicitModules map[string]bool
	identityBuilder IdentityRecordBuilder
}

type EngineOption func(*Engine)
type IdentityRecordBuilder func(context.Context, *InvestigationReport) any

func NewEngine(modules []Module, opts ...EngineOption) *Engine {
	engine := &Engine{
		modules: modules,
		timeout: DefaultModuleTimeout,
	}
	for _, opt := range opts {
		opt(engine)
	}
	return engine
}

func WithModuleTimeout(timeout time.Duration) EngineOption {
	return func(engine *Engine) {
		if timeout > 0 {
			engine.timeout = timeout
		}
	}
}

func WithPassive(passive bool) EngineOption {
	return func(engine *Engine) {
		engine.passive = passive
	}
}

func WithActive(active bool) EngineOption {
	return func(engine *Engine) {
		engine.active = active
	}
}

func WithSelectedModules(names map[string]bool) EngineOption {
	return func(engine *Engine) {
		if len(names) == 0 {
			engine.explicitModules = nil
			return
		}
		engine.explicitModules = make(map[string]bool, len(names))
		for name, selected := range names {
			if selected {
				engine.explicitModules[name] = true
			}
		}
	}
}

func WithIdentityRecordBuilder(builder IdentityRecordBuilder) EngineOption {
	return func(engine *Engine) {
		engine.identityBuilder = builder
	}
}

func (e *Engine) Run(ctx context.Context, number *PhoneNumber) (*InvestigationReport, error) {
	results := make([]*ModuleResult, len(e.modules))
	ctx = ContextWithResponseCache(ctx, NewResponseCache())
	group, groupCtx := errgroup.WithContext(ctx)

	for i, module := range e.modules {
		i, module := i, module
		group.Go(func() error {
			results[i] = e.runModule(groupCtx, module, number)
			return nil
		})
	}

	if err := group.Wait(); err != nil {
		return nil, fmt.Errorf("run modules: %w", err)
	}

	report := &InvestigationReport{
		GeneratedAt: time.Now().UTC(),
		Passive:     e.passive,
		Number:      number,
		Results:     results,
		PivotChain: &PivotChainNode{
			Type:     "phone",
			Value:    number.E164,
			Depth:    0,
			Source:   "primary",
			Children: []*PivotChainNode{},
		},
	}
	mergeTruecallerSpamFindings(report.Results)
	report.Messenger = BuildMessengerReport(results)

	// Second pass: modules that depend on the completed MessengerReport.
	for i, module := range e.modules {
		pmm, ok := module.(PostMessengerModule)
		if !ok {
			continue
		}
		if results[i] != nil && results[i].Status == ModuleStatusGated {
			continue
		}
		results[i] = e.runPostMessengerModule(groupCtx, module.Name(), pmm, number, report)
	}
	report.ImageIntelligence = extractImageIntelResult(results)

	report.IdentityGraph = BuildIdentityGraph(report)
	report.Timeline = BuildTimeline(report)
	if e.identityBuilder != nil {
		report.IdentityRecord = e.identityBuilder(ctx, report)
	}
	report.RiskScore = ScoreRisk(report)
	return report, nil
}

func (e *Engine) runModule(ctx context.Context, module Module, number *PhoneNumber) (result *ModuleResult) {
	moduleCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	defer func() {
		if recovered := recover(); recovered != nil {
			err := fmt.Errorf("panic: %v", recovered)
			debugf("module %s panicked: %v", module.Name(), recovered)
			result = erroredModuleResult(module.Name(), err)
		}
	}()

	if module.Tier() == TierActive && !e.active && !e.isExplicitlySelected(module.Name()) {
		return gatedModuleResult(module.Name())
	}

	if err := module.DryRun(moduleCtx, number); err != nil {
		return skippedModuleResult(module.Name(), err)
	}

	if e.passive {
		if passiveModule, ok := module.(PassiveModule); ok {
			result, err := passiveModule.RunPassive(moduleCtx, number)
			if err != nil {
				return erroredModuleResult(module.Name(), err)
			}
			if result == nil {
				return &ModuleResult{
					ModuleName: module.Name(),
					Status:     ModuleStatusSkipped,
					Findings:   map[string]string{},
					Evidence:   []string{"module returned no passive result"},
				}
			}
			if result.ModuleName == "" {
				result.ModuleName = module.Name()
			}
			if result.Findings == nil {
				result.Findings = map[string]string{}
			}
			return result
		}
	}

	result, err := module.Run(moduleCtx, number)
	if err != nil {
		return erroredModuleResult(module.Name(), err)
	}
	if result == nil {
		return &ModuleResult{
			ModuleName: module.Name(),
			Status:     ModuleStatusSkipped,
			Findings:   map[string]string{},
			Evidence:   []string{"module returned no result"},
		}
	}
	if result.ModuleName == "" {
		result.ModuleName = module.Name()
	}
	if result.Findings == nil {
		result.Findings = map[string]string{}
	}
	return result
}

func (e *Engine) runPostMessengerModule(ctx context.Context, name string, pmm PostMessengerModule, number *PhoneNumber, report *InvestigationReport) (result *ModuleResult) {
	moduleCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	defer func() {
		if recovered := recover(); recovered != nil {
			err := fmt.Errorf("panic: %v", recovered)
			debugf("post-messenger module %s panicked: %v", name, recovered)
			result = erroredModuleResult(name, err)
		}
	}()

	result, err := pmm.RunPostMessenger(moduleCtx, number, report)
	if err != nil {
		return erroredModuleResult(name, err)
	}
	if result == nil {
		return &ModuleResult{
			ModuleName: name,
			Status:     ModuleStatusSkipped,
			Findings:   map[string]string{},
			Evidence:   []string{"post-messenger module returned no result"},
		}
	}
	if result.ModuleName == "" {
		result.ModuleName = name
	}
	if result.Findings == nil {
		result.Findings = map[string]string{}
	}
	return result
}

func extractImageIntelResult(results []*ModuleResult) *ImageIntelResult {
	for _, result := range results {
		if result == nil || result.ModuleName != "image_intelligence" || result.Data == nil {
			continue
		}
		if ir, ok := result.Data.(*ImageIntelResult); ok {
			return ir
		}
	}
	return nil
}

func (e *Engine) isExplicitlySelected(name string) bool {
	if len(e.explicitModules) == 0 {
		return false
	}
	return e.explicitModules[name]
}

func skippedModuleResult(name string, err error) *ModuleResult {
	reason := ""
	if err != nil {
		reason = err.Error()
	}
	return &ModuleResult{
		ModuleName: name,
		Status:     ModuleStatusSkipped,
		Findings: map[string]string{
			"skipped": "true",
			"reason":  reason,
		},
		Evidence: []string{reason},
	}
}

func gatedModuleResult(name string) *ModuleResult {
	reason := fmt.Sprintf("active module: use --active or --modules %s to enable", name)
	return &ModuleResult{
		ModuleName: name,
		Status:     ModuleStatusGated,
		Findings: map[string]string{
			"gated":  "true",
			"reason": reason,
		},
		Evidence: []string{reason},
	}
}

func erroredModuleResult(name string, err error) *ModuleResult {
	return &ModuleResult{
		ModuleName: name,
		Status:     ModuleStatusError,
		Findings: map[string]string{
			"error": err.Error(),
		},
		Evidence: []string{err.Error()},
	}
}

func debugf(format string, args ...any) {
	if os.Getenv("PHONEACCESS_DEBUG") == "" {
		return
	}
	log.Printf("[debug] "+format, args...)
}

func mergeTruecallerSpamFindings(results []*ModuleResult) {
	var tags []string
	for _, result := range results {
		if result == nil || !strings.EqualFold(result.ModuleName, "truecaller") || len(result.Findings) == 0 {
			continue
		}
		tags = splitRiskList(result.Findings["tags"])
		if len(tags) > 0 {
			break
		}
	}
	if len(tags) == 0 {
		return
	}

	for _, result := range results {
		if result == nil || !strings.EqualFold(result.ModuleName, "spam") {
			continue
		}
		if result.Findings == nil {
			result.Findings = map[string]string{}
		}
		merged := mergeUniqueRiskTags(splitRiskList(result.Findings["truecaller_tags"]), tags)
		if len(merged) > 0 {
			result.Findings["truecaller_tags"] = strings.Join(merged, ", ")
			if strings.TrimSpace(result.Findings["caller_type"]) == "" || strings.EqualFold(strings.TrimSpace(result.Findings["caller_type"]), "unknown") {
				for _, tag := range merged {
					switch strings.ToLower(strings.TrimSpace(tag)) {
					case "spam", "telemarketer":
						result.Findings["caller_type"] = tag
						goto nextResult
					}
				}
			}
		}
	nextResult:
	}
}

func mergeUniqueRiskTags(existing, incoming []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(existing)+len(incoming))
	for _, tag := range existing {
		cleaned := strings.TrimSpace(tag)
		if cleaned == "" {
			continue
		}
		key := strings.ToLower(cleaned)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, cleaned)
	}
	for _, tag := range incoming {
		cleaned := strings.TrimSpace(tag)
		if cleaned == "" {
			continue
		}
		key := strings.ToLower(cleaned)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, cleaned)
	}
	return out
}
