package callerkit

import (
	"context"
	"strings"
	"testing"
)

func TestCallerKitSkippedForNonMENANumber(t *testing.T) {
	source := New(WithAPIKey("key"))
	err := source.DryRun(context.Background(), "+14155552671")
	if err == nil || !strings.Contains(err.Error(), "MENA") {
		t.Fatalf("DryRun() error = %v, want MENA skip", err)
	}
}
