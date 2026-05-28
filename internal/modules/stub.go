package modules

import (
	"context"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

type StubModule struct{}

func NewStubModule() *StubModule {
	return &StubModule{}
}

func (m *StubModule) Name() string {
	return "phase1-stub"
}

func (m *StubModule) Description() string {
	return "Offline placeholder for future OSINT modules."
}

func (m *StubModule) RequiresAPIKey() bool {
	return false
}

func (m *StubModule) Tier() core.ModuleTier {
	return core.TierPassive
}

func (m *StubModule) DryRun(ctx context.Context, number *core.PhoneNumber) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (m *StubModule) Run(ctx context.Context, number *core.PhoneNumber) (*core.ModuleResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	return &core.ModuleResult{
		ModuleName: m.Name(),
		Status:     core.ModuleStatusSkipped,
		Findings:   map[string]string{},
		Evidence:   []string{"Phase 1 does not perform OSINT network calls."},
	}, nil
}
