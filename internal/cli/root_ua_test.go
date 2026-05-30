package cli

import (
	"testing"

	"github.com/KatrielMoses/PhoneAccess/internal/config"
	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

func TestUserAgentFlagOverridesEnvConfigKey(t *testing.T) {
	const flagUA = "FlagAgent/1.0"
	const envUA = "EnvAgent/1.0"

	// Lower-priority: env var config key.
	t.Setenv("PHONEACCESS_USER_AGENT", envUA)
	t.Cleanup(func() { core.InitGlobalPool(core.UAModeFixed, "") })

	opts := &options{userAgent: flagUA, uaMode: ""}
	resolveAndInitUA(opts, (*config.Store)(nil))

	if got := core.GetGlobalPool().GetUA(); got != flagUA {
		t.Fatalf("--user-agent flag %q should override env %q, got %q", flagUA, envUA, got)
	}
}

func TestUAModeRandomActivatesRandomPool(t *testing.T) {
	t.Cleanup(func() { core.InitGlobalPool(core.UAModeFixed, "") })

	opts := &options{uaMode: "random"}
	resolveAndInitUA(opts, (*config.Store)(nil))

	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		seen[core.GetGlobalPool().GetUA()] = true
	}
	if len(seen) < 2 {
		t.Fatal("ua-mode=random should produce varied UAs across 100 calls")
	}
}

func TestUAModeDefaultIsFixed(t *testing.T) {
	t.Cleanup(func() { core.InitGlobalPool(core.UAModeFixed, "") })

	opts := &options{}
	resolveAndInitUA(opts, (*config.Store)(nil))

	first := core.GetGlobalPool().GetUA()
	for i := 0; i < 20; i++ {
		if ua := core.GetGlobalPool().GetUA(); ua != first {
			t.Fatalf("default mode should be fixed: got %q on call %d, expected %q", ua, i, first)
		}
	}
}
