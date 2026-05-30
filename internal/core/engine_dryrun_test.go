package core

import (
	"context"
	"errors"
	"testing"
)

func TestEngineGatesActiveModulesByDefault(t *testing.T) {
	active := &recordingModule{name: "active", tier: TierActive}
	passive := &recordingModule{name: "passive", tier: TierPassive}

	engine := NewEngine([]Module{active, passive})
	report, err := engine.Run(context.Background(), &PhoneNumber{E164: "+14155552671"})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if got := report.Results[0].Status; got != ModuleStatusGated {
		t.Fatalf("active status = %s, want gated", got)
	}
	if got := report.Results[0].Findings["reason"]; got != "active module: use --active or --modules active to enable" {
		t.Fatalf("active reason = %q", got)
	}
	if active.runCount != 0 || active.dryRunCount != 0 {
		t.Fatalf("active module should not execute; got dryRun=%d run=%d", active.dryRunCount, active.runCount)
	}
	if got := report.Results[1].Status; got != ModuleStatusSuccess {
		t.Fatalf("passive status = %s, want success", got)
	}
	if passive.runCount != 1 || passive.dryRunCount != 1 {
		t.Fatalf("passive module should execute once; got dryRun=%d run=%d", passive.dryRunCount, passive.runCount)
	}
}

func TestEngineRunsActiveModulesWhenEnabled(t *testing.T) {
	active := &recordingModule{name: "active", tier: TierActive}
	engine := NewEngine([]Module{active}, WithActive(true))

	report, err := engine.Run(context.Background(), &PhoneNumber{E164: "+14155552671"})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := report.Results[0].Status; got != ModuleStatusSuccess {
		t.Fatalf("active status = %s, want success", got)
	}
	if active.runCount != 1 || active.dryRunCount != 1 {
		t.Fatalf("active module should execute once; got dryRun=%d run=%d", active.dryRunCount, active.runCount)
	}
}

func TestEngineRunsExplicitActiveModuleWhenSelected(t *testing.T) {
	active := &recordingModule{name: "active", tier: TierActive}
	engine := NewEngine([]Module{active}, WithSelectedModules(map[string]bool{"active": true}))

	report, err := engine.Run(context.Background(), &PhoneNumber{E164: "+14155552671"})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := report.Results[0].Status; got != ModuleStatusSuccess {
		t.Fatalf("active status = %s, want success", got)
	}
	if active.runCount != 1 || active.dryRunCount != 1 {
		t.Fatalf("active module should execute once; got dryRun=%d run=%d", active.dryRunCount, active.runCount)
	}
}

func TestTruecallerTagsMergeIntoSpamFindings(t *testing.T) {
	engine := NewEngine([]Module{
		staticModule{
			name: "truecaller",
			tier: TierActive,
			findings: map[string]string{
				"tags": "spam, telemarketer",
			},
		},
		staticModule{
			name: "spam",
			tier: TierPassive,
			findings: map[string]string{
				"caller_type": "unknown",
			},
		},
	}, WithActive(true))

	report, err := engine.Run(context.Background(), &PhoneNumber{E164: "+14155552671"})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	spam := moduleFindings(report, "spam")
	if got := spam["truecaller_tags"]; got != "spam, telemarketer" {
		t.Fatalf("truecaller_tags = %q, want merged tags", got)
	}
	if got := spam["caller_type"]; got != "spam" {
		t.Fatalf("caller_type = %q, want Truecaller spam label to merge", got)
	}
}

func TestEnginePropagatesDryRunSkipToReport(t *testing.T) {
	dryRunFakeRan = false
	engine := NewEngine([]Module{dryRunFakeModule{dryErr: errors.New("missing key"), tier: TierPassive}})
	report, err := engine.Run(context.Background(), &PhoneNumber{E164: "+14155552671"})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(report.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(report.Results))
	}
	result := report.Results[0]
	if result.Status != ModuleStatusSkipped || result.Findings["reason"] != "missing key" {
		t.Fatalf("result = %#v", result)
	}
	if dryRunFakeRan {
		t.Fatal("Run called after DryRun failure")
	}
}

var dryRunFakeRan bool

type dryRunFakeModule struct {
	dryErr error
	tier   ModuleTier
}

func (m dryRunFakeModule) Name() string                               { return "fake" }
func (m dryRunFakeModule) Description() string                        { return "fake" }
func (m dryRunFakeModule) RequiresAPIKey() bool                       { return true }
func (m dryRunFakeModule) Tier() ModuleTier                           { return m.tier }
func (m dryRunFakeModule) DryRun(context.Context, *PhoneNumber) error { return m.dryErr }
func (m dryRunFakeModule) Run(context.Context, *PhoneNumber) (*ModuleResult, error) {
	dryRunFakeRan = true
	return &ModuleResult{ModuleName: "fake", Status: ModuleStatusSuccess}, nil
}

type staticModule struct {
	name     string
	tier     ModuleTier
	findings map[string]string
}

func (m staticModule) Name() string                               { return m.name }
func (m staticModule) Description() string                        { return m.name }
func (m staticModule) RequiresAPIKey() bool                       { return false }
func (m staticModule) Tier() ModuleTier                           { return m.tier }
func (m staticModule) DryRun(context.Context, *PhoneNumber) error { return nil }
func (m staticModule) Run(context.Context, *PhoneNumber) (*ModuleResult, error) {
	return &ModuleResult{
		ModuleName: m.name,
		Status:     ModuleStatusSuccess,
		Findings:   m.findings,
	}, nil
}

type recordingModule struct {
	name        string
	tier        ModuleTier
	dryRunCount int
	runCount    int
}

func (m *recordingModule) Name() string         { return m.name }
func (m *recordingModule) Description() string  { return m.name }
func (m *recordingModule) RequiresAPIKey() bool { return false }
func (m *recordingModule) Tier() ModuleTier     { return m.tier }
func (m *recordingModule) DryRun(context.Context, *PhoneNumber) error {
	m.dryRunCount++
	return nil
}
func (m *recordingModule) Run(context.Context, *PhoneNumber) (*ModuleResult, error) {
	m.runCount++
	return &ModuleResult{ModuleName: m.name, Status: ModuleStatusSuccess}, nil
}

func (m dryRunFakeModule) ProxyAware() bool { return true }

func (m staticModule) ProxyAware() bool { return true }

func (m *recordingModule) ProxyAware() bool { return true }
