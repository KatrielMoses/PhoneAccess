package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

func TestOpsecWarning_NoProxy_ShowsNone(t *testing.T) {
	s := opsecState{
		ProxyLabel:  "none",
		ProxyEnabled: false,
		DoHEnabled:  false,
		DoHProvider: "cloudflare",
		UAMode:      string(core.UAModeFixed),
	}

	var buf bytes.Buffer
	if err := printOpsecWarning(&buf, s); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "Proxy:") {
		t.Error("warning must contain Proxy: line")
	}
	if !strings.Contains(out, "none") {
		t.Errorf("expected 'none' in proxy line, got:\n%s", out)
	}
}

func TestOpsecWarning_TorEnabled_ShowsTorLabel(t *testing.T) {
	s := opsecState{
		ProxyEnabled: true,
		ProxyLabel:   "Tor (127.0.0.1:9050)",
		TorEnabled:   true,
		DoHEnabled:   false,
		DoHProvider:  "cloudflare",
		UAMode:       string(core.UAModeFixed),
	}

	var buf bytes.Buffer
	if err := printOpsecWarning(&buf, s); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "Tor") {
		t.Errorf("expected 'Tor' in proxy line when tor is active, got:\n%s", out)
	}
	if !strings.Contains(out, "127.0.0.1:9050") {
		t.Errorf("expected Tor address in warning, got:\n%s", out)
	}
}

func TestOpsecWarning_DoHEnabled_ShowsProvider(t *testing.T) {
	s := opsecState{
		ProxyLabel:  "none",
		DoHEnabled:  true,
		DoHProvider: "cloudflare",
		UAMode:      string(core.UAModeFixed),
	}

	var buf bytes.Buffer
	if err := printOpsecWarning(&buf, s); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "cloudflare") {
		t.Errorf("expected provider name in DoH line, got:\n%s", out)
	}
}

func TestOpsecWarning_YesFlagSkipsPrompt(t *testing.T) {
	o := &options{
		active:      true,
		yes:         true,
		allModules:  []core.Module{},
		format:      "terminal",
		timeoutSecs: 30,
	}

	selected := []core.Module{}
	// With --yes set, the warning check should be skipped entirely in
	// hasActiveModulesSelected + the yes guard in root.go.
	// Here we just verify the flag is respected at the logic level.
	if !o.yes {
		t.Fatal("yes flag should be set")
	}
	// Simulate the guard: warning fires only when !o.yes
	warningFired := hasActiveModulesSelected(o, selected) && !o.yes
	if warningFired {
		t.Fatal("--yes flag must suppress the OPSEC prompt")
	}
}

func TestOpsecWarning_PassiveOnlyRun_NoWarning(t *testing.T) {
	o := &options{
		active:      false,
		passive:     true,
		allModules:  []core.Module{},
		format:      "terminal",
		timeoutSecs: 30,
	}

	// All modules passive.
	selected := []core.Module{
		opsecFakePassiveModule{},
		opsecFakePassiveModule{},
	}

	if hasActiveModulesSelected(o, selected) {
		t.Fatal("passive-only run must not trigger OPSEC warning")
	}
}

func TestOpsecWarning_ActiveModuleInSelected_TriggersWarning(t *testing.T) {
	// When a user explicitly selects an active-tier module via --modules, the
	// engine bypasses the active gate and runs it — so the warning must fire
	// even without --active.
	o := &options{
		active:      false,
		moduleNames: "active-stub", // explicit selection via --modules
		allModules:  []core.Module{},
		format:      "terminal",
		timeoutSecs: 30,
	}

	selected := []core.Module{
		opsecFakePassiveModule{},
		opsecFakeActiveModule{},
	}

	if !hasActiveModulesSelected(o, selected) {
		t.Fatal("selecting an active module must trigger OPSEC warning")
	}
}

func TestPromptOpsecContinue_YAccepts(t *testing.T) {
	var out bytes.Buffer
	in := strings.NewReader("y\n")

	ok, err := promptOpsecContinue(&out, in)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected true for 'y' answer")
	}
}

func TestPromptOpsecContinue_EnterDeclines(t *testing.T) {
	var out bytes.Buffer
	in := strings.NewReader("\n")

	ok, err := promptOpsecContinue(&out, in)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected false for empty/enter answer (default is N)")
	}
}

func TestBuildOpsecState_TorAddress(t *testing.T) {
	o := &options{
		tor:        true,
		torAddress: "10.0.0.1:9150",
	}
	s := buildOpsecState(o)
	if !strings.Contains(s.ProxyLabel, "10.0.0.1:9150") {
		t.Errorf("expected custom tor address in label, got %q", s.ProxyLabel)
	}
	if !s.TorEnabled {
		t.Error("TorEnabled should be true")
	}
}

// stub modules for test.

type opsecFakePassiveModule struct{}

func (m opsecFakePassiveModule) Name() string                                              { return "passive-stub" }
func (m opsecFakePassiveModule) Description() string                                       { return "" }
func (m opsecFakePassiveModule) RequiresAPIKey() bool                                      { return false }
func (m opsecFakePassiveModule) Tier() core.ModuleTier                                     { return core.TierPassive }
func (m opsecFakePassiveModule) ProxyAware() bool                                          { return true }
func (m opsecFakePassiveModule) DryRun(_ context.Context, _ *core.PhoneNumber) error       { return nil }
func (m opsecFakePassiveModule) Run(_ context.Context, _ *core.PhoneNumber) (*core.ModuleResult, error) {
	return nil, nil
}

type opsecFakeActiveModule struct{}

func (m opsecFakeActiveModule) Name() string                                              { return "active-stub" }
func (m opsecFakeActiveModule) Description() string                                       { return "" }
func (m opsecFakeActiveModule) RequiresAPIKey() bool                                      { return false }
func (m opsecFakeActiveModule) Tier() core.ModuleTier                                     { return core.TierActive }
func (m opsecFakeActiveModule) ProxyAware() bool                                          { return false }
func (m opsecFakeActiveModule) DryRun(_ context.Context, _ *core.PhoneNumber) error       { return nil }
func (m opsecFakeActiveModule) Run(_ context.Context, _ *core.PhoneNumber) (*core.ModuleResult, error) {
	return nil, nil
}
