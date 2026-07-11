package server

import (
	"encoding/json"
	"log/slog"
	"os"
	"time"
)

// serviceDomainState is the persisted view of one service's domain source.
type serviceDomainState struct {
	Domains   []string  `json:"domains"`
	ETag      string    `json:"etag,omitempty"`
	FetchedAt time.Time `json:"fetched_at"`
}

// dynamicDomainsState is the on-disk schema of dynamic-domains.state.
type dynamicDomainsState struct {
	Services   map[string]*serviceDomainState `json:"services"`
	Quarantine map[string]quarantineEntry     `json:"quarantine"`
	SavedAt    time.Time                      `json:"saved_at"`
}

// loadState restores the last-known domain sets and quarantine records, so
// certificates can be served at boot without the app being up.
func (dm *DynamicDomainManager) loadState() {
	if dm.config.StatePath == "" {
		return
	}

	data, err := os.ReadFile(dm.config.StatePath)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("Failed to read dynamic domains state", "path", dm.config.StatePath, "error", err)
		}
		return
	}

	var state dynamicDomainsState
	if err := json.Unmarshal(data, &state); err != nil {
		slog.Warn("Failed to parse dynamic domains state", "path", dm.config.StatePath, "error", err)
		return
	}

	dm.mu.Lock()
	if state.Services != nil {
		dm.states = state.Services
	}
	dm.mu.Unlock()

	dm.quarantine.Restore(state.Quarantine)

	slog.Info("Restored dynamic domains state",
		"path", dm.config.StatePath,
		"services", len(state.Services),
		"quarantined", len(state.Quarantine),
	)
}

// saveState persists the domain sets and quarantine records atomically.
func (dm *DynamicDomainManager) saveState() {
	if dm.config.StatePath == "" {
		return
	}

	dm.mu.Lock()
	services := make(map[string]*serviceDomainState, len(dm.states))
	for name, state := range dm.states {
		services[name] = state
	}
	dm.mu.Unlock()

	state := dynamicDomainsState{
		Services:   services,
		Quarantine: dm.quarantine.Snapshot(),
		SavedAt:    time.Now(),
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		slog.Warn("Failed to marshal dynamic domains state", "error", err)
		return
	}

	tmpPath := dm.config.StatePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		slog.Warn("Failed to write dynamic domains state", "path", tmpPath, "error", err)
		return
	}

	if err := os.Rename(tmpPath, dm.config.StatePath); err != nil {
		slog.Warn("Failed to save dynamic domains state", "path", dm.config.StatePath, "error", err)
	}
}
