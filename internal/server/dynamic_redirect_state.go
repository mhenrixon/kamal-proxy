package server

import (
	"encoding/json"
	"log/slog"
	"os"
	"time"
)

// serviceRedirectState is the persisted view of one service's redirects
// source: the raw host map as the app sent it, recompiled at boot.
type serviceRedirectState struct {
	Hosts     map[string]redirectHostConfig `json:"hosts"`
	ETag      string                        `json:"etag,omitempty"`
	FetchedAt time.Time                     `json:"fetched_at"`
	// Source records which endpoint the state came from, so a redeploy with a
	// different source drops the ETag instead of sending the new endpoint a
	// tag it never issued.
	Source string `json:"source,omitempty"`
}

// dynamicRedirectsState is the on-disk schema of dynamic-redirects.state.
type dynamicRedirectsState struct {
	Services map[string]*serviceRedirectState `json:"services"`
	SavedAt  time.Time                        `json:"saved_at"`
}

// loadState restores the last good redirect maps, so a reboot serves
// redirects without the app being up.
func (dm *DynamicRedirectManager) loadState() {
	if dm.config.StatePath == "" {
		return
	}

	data, err := os.ReadFile(dm.config.StatePath)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("Failed to read dynamic redirects state", "path", dm.config.StatePath, "error", err)
		}
		return
	}

	var state dynamicRedirectsState
	if err := json.Unmarshal(data, &state); err != nil {
		slog.Warn("Failed to parse dynamic redirects state", "path", dm.config.StatePath, "error", err)
		return
	}

	dm.mu.Lock()
	for name, serviceState := range state.Services {
		// Guard against hand-edited or partially written files.
		if serviceState == nil {
			slog.Warn("Skipping invalid dynamic redirects state entry", "service", name)
			continue
		}
		dm.states[name] = serviceState
	}
	dm.mu.Unlock()

	slog.Info("Restored dynamic redirects state",
		"path", dm.config.StatePath,
		"services", len(state.Services),
	)
}

// saveState persists the last good redirect maps atomically. Writers are
// serialized: concurrent polls share one temp file path, and the snapshot of
// one save must not interleave with another's write.
func (dm *DynamicRedirectManager) saveState() {
	if dm.config.StatePath == "" {
		return
	}

	dm.saveLock.Lock()
	defer dm.saveLock.Unlock()

	dm.mu.Lock()
	services := make(map[string]*serviceRedirectState, len(dm.states))
	for name, state := range dm.states {
		services[name] = state
	}
	dm.mu.Unlock()

	state := dynamicRedirectsState{
		Services: services,
		SavedAt:  time.Now(),
	}

	data, err := json.Marshal(state)
	if err != nil {
		slog.Warn("Failed to marshal dynamic redirects state", "error", err)
		return
	}

	if err := writeFileAtomic(dm.config.StatePath, data, 0600); err != nil {
		slog.Warn("Failed to save dynamic redirects state", "path", dm.config.StatePath, "error", err)
	}
}
