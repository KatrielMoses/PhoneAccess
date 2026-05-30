package cli

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

func TestReadBatchNumbersSkipsBlanksAndComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "phones.txt")
	input := "\n# comment\n+14155552671\n  \n+12125550100\n"
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	numbers, err := readBatchNumbers(path)
	if err != nil {
		t.Fatalf("readBatchNumbers() error = %v", err)
	}
	want := []string{"+14155552671", "+12125550100"}
	if strings.Join(numbers, "|") != strings.Join(want, "|") {
		t.Fatalf("numbers = %#v, want %#v", numbers, want)
	}
}

func TestBatchOutputPathsUseTimestamp(t *testing.T) {
	now := time.Date(2026, 5, 27, 6, 7, 8, 0, time.UTC)
	csvPath, jsonPath := batchOutputPaths(now)
	if csvPath != "phoneaccess_batch_20260527_060708.csv" {
		t.Fatalf("csv path = %q", csvPath)
	}
	if jsonPath != "phoneaccess_batch_20260527_060708.json" {
		t.Fatalf("json path = %q", jsonPath)
	}
}

func TestSelectModulesAcceptsCorrelatorPseudoModule(t *testing.T) {
	modules, err := selectModules([]core.Module{
		batchFakeModule{name: "carrier"},
		batchFakeModule{name: "spam"},
	}, "carrier,correlator")
	if err != nil {
		t.Fatalf("selectModules() error = %v", err)
	}
	if !identityRecordSelected("carrier,correlator") {
		t.Fatal("identityRecordSelected() = false, want true")
	}
	if modules[0].Name() != "carrier" {
		t.Fatalf("modules[0] = %q, want carrier", modules[0].Name())
	}
	if modules[1].Name() != "spam" {
		t.Fatalf("modules[1] = %q, want spam", modules[1].Name())
	}
	result, err := modules[1].Run(context.Background(), &core.PhoneNumber{})
	if err != nil {
		t.Fatalf("run skipped module: %v", err)
	}
	if result.Status != core.ModuleStatusSkipped {
		t.Fatalf("spam status = %s, want skipped", result.Status)
	}
}

func TestBatchSingleNumberProducesOneCSVRowAndOneJSONReport(t *testing.T) {
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("change working directory: %v", err)
	}
	defer func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	}()

	inputPath := filepath.Join(dir, "phones.txt")
	if err := os.WriteFile(inputPath, []byte("+14155552671\n"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	opts := &options{
		timeoutSecs: 30,
		allModules:  []core.Module{batchFakeModule{name: "spam"}},
	}
	now := time.Date(2026, 5, 27, 6, 7, 8, 0, time.UTC)
	var out bytes.Buffer
	if err := opts.runBatch(context.Background(), &out, inputPath, func() time.Time { return now }); err != nil {
		t.Fatalf("runBatch() error = %v\noutput:\n%s", err, out.String())
	}

	csvPath := filepath.Join(dir, "phoneaccess_batch_20260527_060708.csv")
	csvFile, err := os.Open(csvPath)
	if err != nil {
		t.Fatalf("open csv output: %v", err)
	}
	defer csvFile.Close()
	records, err := csv.NewReader(csvFile).ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("csv records = %d, want header and one row", len(records))
	}

	jsonBytes, err := os.ReadFile(filepath.Join(dir, "phoneaccess_batch_20260527_060708.json"))
	if err != nil {
		t.Fatalf("read json output: %v", err)
	}
	var reports []core.InvestigationReport
	if err := json.Unmarshal(jsonBytes, &reports); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("json reports = %d, want 1", len(reports))
	}
	if reports[0].Number == nil || reports[0].Number.E164 != "+14155552671" {
		t.Fatalf("json report number = %#v", reports[0].Number)
	}
}

func TestBatchActiveFlagRunsActiveModules(t *testing.T) {
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("change working directory: %v", err)
	}
	defer func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	}()

	inputPath := filepath.Join(dir, "phones.txt")
	if err := os.WriteFile(inputPath, []byte("+14155552671\n"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	opts := &options{
		timeoutSecs: 30,
		active:      true,
		yes:         true, // skip OPSEC prompt in non-interactive test
		allModules:  []core.Module{batchFakeModule{name: "enumerator", tier: core.TierActive}},
	}
	now := time.Date(2026, 5, 27, 6, 7, 8, 0, time.UTC)
	var out bytes.Buffer
	if err := opts.runBatch(context.Background(), &out, inputPath, func() time.Time { return now }); err != nil {
		t.Fatalf("runBatch() error = %v\noutput:\n%s", err, out.String())
	}

	jsonBytes, err := os.ReadFile(filepath.Join(dir, "phoneaccess_batch_20260527_060708.json"))
	if err != nil {
		t.Fatalf("read json output: %v", err)
	}
	var reports []core.InvestigationReport
	if err := json.Unmarshal(jsonBytes, &reports); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("json reports = %d, want 1", len(reports))
	}
	if got := reports[0].Results[0].Status; got != core.ModuleStatusSuccess {
		t.Fatalf("active module status = %s, want success", got)
	}
}

type batchFakeModule struct {
	name string
	tier core.ModuleTier
}

func (m batchFakeModule) Name() string {
	return m.name
}

func (m batchFakeModule) Description() string {
	return "fake batch module"
}

func (m batchFakeModule) RequiresAPIKey() bool {
	return false
}

func (m batchFakeModule) Tier() core.ModuleTier {
	if m.tier == 0 {
		return core.TierPassive
	}
	return m.tier
}

func (m batchFakeModule) DryRun(ctx context.Context, number *core.PhoneNumber) error {
	return nil
}

func (m batchFakeModule) Run(ctx context.Context, number *core.PhoneNumber) (*core.ModuleResult, error) {
	return &core.ModuleResult{
		ModuleName: m.name,
		Status:     core.ModuleStatusSuccess,
		Findings: map[string]string{
			"spam_score": "0",
		},
	}, nil
}

func (m batchFakeModule) ProxyAware() bool { return true }
