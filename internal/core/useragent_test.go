package core

import (
	"testing"
)

func TestUAPoolFixedModeIsConsistentAcrossRequests(t *testing.T) {
	pool := NewUserAgentPool(UAModeFixed, "")
	first, _ := pool.Get()
	if first == "" {
		t.Fatal("fixed mode returned empty UA")
	}
	for i := 0; i < 100; i++ {
		ua, _ := pool.Get()
		if ua != first {
			t.Fatalf("fixed mode returned different UA on call %d: %q vs %q", i, ua, first)
		}
	}
}

func TestUAPoolRandomModeVariesAcrossRequests(t *testing.T) {
	pool := NewUserAgentPool(UAModeRandom, "")
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		ua, _ := pool.Get()
		seen[ua] = true
	}
	if len(seen) < 2 {
		t.Fatalf("random mode returned only 1 unique UA across 100 requests; expected variation")
	}
}

func TestUAPoolCustomModeUsesExactString(t *testing.T) {
	const want = "MyBot/2.0 (compatible; special)"
	pool := NewUserAgentPool(UAModeCustom, want)
	for i := 0; i < 10; i++ {
		ua, _ := pool.Get()
		if ua != want {
			t.Fatalf("custom mode returned %q, want %q", ua, want)
		}
	}
}

func TestUAPoolFixedModePicksFromEmbeddedPool(t *testing.T) {
	pool := NewUserAgentPool(UAModeFixed, "")
	ua, _ := pool.Get()
	found := false
	for _, e := range pool.entries {
		if e.UA == ua {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("fixed UA %q not found in embedded pool", ua)
	}
}

func TestUAPoolGetUAMatchesGet(t *testing.T) {
	pool := NewUserAgentPool(UAModeFixed, "")
	ua1 := pool.GetUA()
	ua2, _ := pool.Get()
	if ua1 != ua2 {
		t.Fatalf("GetUA() = %q, Get() = %q; must be identical for fixed mode", ua1, ua2)
	}
}

func TestGetGlobalPoolReturnsNonNil(t *testing.T) {
	p := GetGlobalPool()
	if p == nil {
		t.Fatal("GetGlobalPool() returned nil")
	}
}

func TestInitGlobalPoolOverridesDefault(t *testing.T) {
	const customUA = "TestAgent/1.0"
	InitGlobalPool(UAModeCustom, customUA)
	defer InitGlobalPool(UAModeFixed, "") // restore fixed mode after test

	ua := GetGlobalPool().GetUA()
	if ua != customUA {
		t.Fatalf("after InitGlobalPool(custom, %q), GetUA() = %q", customUA, ua)
	}
}
