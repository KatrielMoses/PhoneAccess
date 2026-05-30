package core

import (
	_ "embed"
	"encoding/json"
	"math/rand"
	"sync"
)

//go:embed data/user_agents.json
var rawUAPool []byte

// UAMode controls how User-Agent strings are selected per request.
type UAMode string

const (
	UAModeFixed  UAMode = "fixed"  // one randomly-selected UA for the entire run (default)
	UAModeRandom UAMode = "random" // new random UA per request
	UAModeCustom UAMode = "custom" // operator-supplied string verbatim
)

// UAEntry is a single entry from the embedded pool.
type UAEntry struct {
	UA      string `json:"ua"`
	Profile string `json:"profile"`
	Brand   string `json:"brand"`
	Version string `json:"version"`
}

type uaPoolFile struct {
	UserAgents []UAEntry `json:"user_agents"`
}

// UserAgentPool selects User-Agent strings according to a configured mode.
type UserAgentPool struct {
	mode    UAMode
	custom  string
	entries []UAEntry
	fixed   UAEntry
}

// NewUserAgentPool builds a pool from the embedded UA list.
// In fixed mode (default) one UA is chosen at construction time and reused for all requests.
func NewUserAgentPool(mode UAMode, custom string) *UserAgentPool {
	var f uaPoolFile
	if err := json.Unmarshal(rawUAPool, &f); err != nil || len(f.UserAgents) == 0 {
		f.UserAgents = []UAEntry{{UA: "Mozilla/5.0", Profile: "chrome_windows", Brand: "Google Chrome", Version: "130"}}
	}
	p := &UserAgentPool{
		mode:    mode,
		custom:  custom,
		entries: f.UserAgents,
	}
	if mode == UAModeFixed {
		p.fixed = f.UserAgents[rand.Intn(len(f.UserAgents))]
	}
	return p
}

// Get returns the UA string and pool entry for the current request.
func (p *UserAgentPool) Get() (string, UAEntry) {
	switch p.mode {
	case UAModeCustom:
		return p.custom, UAEntry{UA: p.custom, Profile: "chrome_windows", Brand: "Google Chrome", Version: "130"}
	case UAModeRandom:
		e := p.entries[rand.Intn(len(p.entries))]
		return e.UA, e
	default: // UAModeFixed
		return p.fixed.UA, p.fixed
	}
}

// GetUA returns just the UA string for the current request.
func (p *UserAgentPool) GetUA() string {
	ua, _ := p.Get()
	return ua
}

// EntryForUA looks up the pool entry matching the given UA string.
// Falls back to a chrome_windows entry if the UA is not in the pool.
func (p *UserAgentPool) EntryForUA(ua string) UAEntry {
	for _, e := range p.entries {
		if e.UA == ua {
			return e
		}
	}
	return UAEntry{UA: ua, Profile: "chrome_windows", Brand: "Google Chrome", Version: "130"}
}

// global pool — initialised once at startup, then read-only.
var (
	globalPoolMu sync.RWMutex
	globalPool   *UserAgentPool
)

// InitGlobalPool sets the process-wide UA pool. Call once at startup before
// creating any HTTP clients. Subsequent calls replace the pool atomically.
func InitGlobalPool(mode UAMode, custom string) {
	p := NewUserAgentPool(mode, custom)
	globalPoolMu.Lock()
	globalPool = p
	globalPoolMu.Unlock()
}

// GetGlobalPool returns the process-wide pool, initialising it with fixed mode
// on first call if InitGlobalPool was never called.
func GetGlobalPool() *UserAgentPool {
	globalPoolMu.RLock()
	p := globalPool
	globalPoolMu.RUnlock()
	if p != nil {
		return p
	}
	globalPoolMu.Lock()
	defer globalPoolMu.Unlock()
	if globalPool == nil {
		globalPool = NewUserAgentPool(UAModeFixed, "")
	}
	return globalPool
}
