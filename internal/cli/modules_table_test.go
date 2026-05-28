package cli

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/KatrielMoses/PhoneAccess/internal/modules"
)

func TestModulesTableShowsTiers(t *testing.T) {
	cmd := newModulesCommand(modules.Registry())
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("RunE() error = %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("modules output too short: %q", out.String())
	}
	if !strings.Contains(lines[0], "Tier") {
		t.Fatalf("header = %q, want tier column", lines[0])
	}

	got := map[string]string{}
	split := regexp.MustCompile(`\s{2,}`)
	for _, line := range lines[1:] {
		parts := split.Split(strings.TrimSpace(line), -1)
		if len(parts) < 4 {
			t.Fatalf("could not parse modules row: %q", line)
		}
		got[parts[0]] = parts[1]
	}

	want := map[string]string{
		"carrier":        "passive",
		"voip":           "passive",
		"enumerator":     "active",
		"finance":        "active",
		"geo":            "passive",
		"spam":           "passive",
		"breach":         "passive",
		"public_records": "active",
		"search":         "active",
		"paste":          "active",
		"reverse":        "passive",
		"truecaller":     "active",
		"telegram":       "active",
		"whatsapp":       "active",
		"phase1-stub":    "passive",
	}

	for name, tier := range want {
		if got[name] != tier {
			t.Fatalf("tier for %s = %q, want %q", name, got[name], tier)
		}
	}
}
