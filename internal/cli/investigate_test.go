package cli

import (
	"bytes"
	"context"
	"testing"
	
	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

func TestNoSaveFlag(t *testing.T) {
	opts := &options{
		format:      "json",
		timeoutSecs: 30,
		allModules:  []core.Module{},
		noSave:      true,
		passive:     true, // fast
	}
	
	var buf bytes.Buffer
	err := opts.runInvestigation(context.Background(), &buf, "+14155552671")
	if err != nil {
		t.Fatalf("runInvestigation failed: %v", err)
	}
	
	// If it didn't panic or error, noSave suppressed storage as expected since we didn't mock a storage db path.
}
