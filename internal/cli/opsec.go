package cli

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

// opsecState captures the resolved OPSEC configuration for display in the warning.
type opsecState struct {
	ProxyEnabled bool
	ProxyLabel   string // "Tor (127.0.0.1:9050)", "socks5://...", "http://...", or "none"
	TorEnabled   bool
	DoHEnabled   bool
	DoHProvider  string // e.g. "cloudflare" or custom URL
	UAMode       string // "fixed", "random", "custom"
}

// buildOpsecState derives the display state from resolved CLI options.
func buildOpsecState(o *options) opsecState {
	s := opsecState{
		UAMode:      o.uaMode,
		DoHEnabled:  o.doh,
		DoHProvider: o.dohProvider,
	}
	if s.UAMode == "" {
		s.UAMode = string(core.UAModeFixed)
	}
	if s.DoHProvider == "" {
		s.DoHProvider = "cloudflare"
	}

	if o.tor {
		s.ProxyEnabled = true
		s.TorEnabled = true
		addr := o.torAddress
		if addr == "" {
			addr = "127.0.0.1:9050"
		}
		s.ProxyLabel = fmt.Sprintf("Tor (%s)", addr)
	} else if o.proxyURL != "" {
		s.ProxyEnabled = true
		s.ProxyLabel = o.proxyURL
	} else {
		s.ProxyLabel = "none"
	}
	return s
}

// printOpsecWarning writes the pre-flight warning block to w.
func printOpsecWarning(w io.Writer, s opsecState) error {
	proxyLine := s.ProxyLabel

	torLine := "disabled"
	if s.TorEnabled {
		torLine = "enabled"
	}

	dohLine := "disabled (DNS may leak to local resolver)"
	if s.DoHEnabled {
		dohLine = fmt.Sprintf("enabled (%s)", s.DoHProvider)
	}

	uaLine := fmt.Sprintf("%s (Chrome/Windows — consistent per run)", s.UAMode)
	if s.UAMode == string(core.UAModeRandom) {
		uaLine = "random (rotated per request)"
	}

	var recs []string
	if !s.ProxyEnabled {
		recs = append(recs, "• Use --tor or --proxy to route requests through anonymising infrastructure")
	}
	if !s.DoHEnabled {
		recs = append(recs, "• Use --doh to prevent DNS leaks")
	}
	if len(recs) == 0 {
		recs = append(recs, "• Configuration looks good for active probing")
	}

	warning := fmt.Sprintf(`
⚠  OPSEC WARNING
   Active modules will probe 277+ platform endpoints directly.

   Current configuration:
   • Proxy:      %s
   • Tor:        %s
   • User-Agent: %s
   • DoH:        %s

   Recommendations:
   %s

`,
		proxyLine,
		torLine,
		uaLine,
		dohLine,
		strings.Join(recs, "\n   "),
	)
	_, err := fmt.Fprint(w, warning)
	return err
}

// promptOpsecContinue prints "Continue? [y/N]: " and returns true if the user
// answers y or Y.  It reads from r.
func promptOpsecContinue(w io.Writer, r io.Reader) (bool, error) {
	if _, err := fmt.Fprint(w, "   Continue? [y/N]: "); err != nil {
		return false, err
	}
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		return false, nil
	}
	answer := strings.TrimSpace(scanner.Text())
	return strings.EqualFold(answer, "y"), scanner.Err()
}

// hasActiveModulesSelected returns true if the investigation will run at least
// one active (TierActive) module.
//
// Without --active and no explicit --modules filter, active-tier modules are
// gated by the engine and will not run, so no OPSEC warning is needed.
// When --modules explicitly names an active-tier module the engine does run it
// (it bypasses the gate via isExplicitlySelected), so we warn in that case too.
func hasActiveModulesSelected(o *options, selected []core.Module) bool {
	if o.active {
		return true
	}
	// No explicit module selection → engine gates all active-tier modules.
	if strings.TrimSpace(o.moduleNames) == "" {
		return false
	}
	for _, m := range selected {
		if m.Tier() == core.TierActive {
			return true
		}
	}
	return false
}
