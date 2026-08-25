package server

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Early release of issuance holds.
//
// The quarantine ladder exists so a domain that cannot be issued does not loop
// against the CA's rate limits. But its steps run to 24 hours, and the usual
// reason a domain cannot be issued is temporary and operator-driven: its DNS
// has not been repointed at this proxy yet. Waiting out a full step after the
// repoint is what makes preparing a cutover in advance feel like a punishment.
//
// The proxy already owns the sensor that answers the question — the pre-flight
// probe. This sweeps the held domains on an interval and lifts the hold from
// any that now route here, so a cutover costs about one probe interval rather
// than a ladder step.

// DefaultReleaseProbeInterval is how often held domains are re-probed. It is
// short because the probe is a single local HTTP request against a name the
// operator already gave us, and because the whole value of the sweep is that a
// repoint is noticed promptly.
const DefaultReleaseProbeInterval = time.Minute

type releaseProberConfig struct {
	// Interval between sweeps. Zero disables the loop entirely.
	Interval time.Duration

	// Preflight probes whether a domain routes back to this proxy.
	Preflight func(domain string) error

	// Unprobeable reports domains the probe cannot speak for — in practice
	// those in a zone with a DNS-01 provider, whose issuance never depended
	// on where they point. Wildcards are always skipped.
	Unprobeable func(domain string) bool

	// Released is notified for each domain whose hold was lifted, so issuance
	// can be requested for it.
	Released func(domain string)

	// OnChange is notified once per sweep that released anything, so the
	// quarantine state can be persisted.
	OnChange func()
}

type releaseProber struct {
	quarantine *domainQuarantine
	config     releaseProberConfig

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newReleaseProber(quarantine *domainQuarantine, config releaseProberConfig) *releaseProber {
	ctx, cancel := context.WithCancel(context.Background())

	return &releaseProber{
		quarantine: quarantine,
		config:     config,
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start launches the sweep loop. A zero interval leaves it dormant.
func (p *releaseProber) Start() {
	if p.config.Interval <= 0 {
		slog.Debug("Release probing disabled")
		return
	}

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()

		ticker := time.NewTicker(p.config.Interval)
		defer ticker.Stop()

		for {
			select {
			case <-p.ctx.Done():
				return
			case <-ticker.C:
				p.sweep()
			}
		}
	}()
}

func (p *releaseProber) Stop() {
	p.cancel()
	p.wg.Wait()
}

// sweep probes every currently-held domain the probe can speak for and lifts
// the hold from those that answer.
//
// A failing probe deliberately records nothing. The domain is already held,
// and counting each sweep as a fresh failure would drive it to the top of the
// ladder within minutes purely for continuing to be in the state it was
// already being held for.
func (p *releaseProber) sweep() {
	candidates := p.candidates()
	if len(candidates) == 0 {
		return
	}

	reachable, _ := probeDomains(candidates, p.config.Preflight, p.config.Unprobeable)
	held := map[string]struct{}{}
	for _, domain := range reachable {
		held[domain] = struct{}{}
	}

	released := []string{}
	for _, domain := range candidates {
		if _, stillFailing := held[domain]; stillFailing {
			continue
		}
		if p.quarantine.Release(domain) {
			released = append(released, domain)
		}
	}

	if len(released) == 0 {
		return
	}

	slog.Info("Domains route here again; lifting issuance holds", "domains", released)

	if p.config.Released != nil {
		for _, domain := range released {
			p.config.Released(domain)
		}
	}
	if p.config.OnChange != nil {
		p.config.OnChange()
	}
}

// candidates lists the domains whose hold this sweep is allowed to lift: those
// actually holding right now, minus rate-limit holds and minus anything the
// probe cannot speak for.
//
// A rate limit is the CA's clock rather than the proxy's backoff — the domain
// routing here again says nothing about it, and ordering inside the window
// both fails and pushes the window further out.
//
// The unprobeable ones must be filtered out here rather than left to
// probeDomains: that function *skips* them, so they come back neither passed
// nor failed, and a sweep that read "not failed" as "passed" would release
// every wildcard and DNS-01 hold on its first tick without probing anything.
func (p *releaseProber) candidates() []string {
	candidates := []string{}
	for domain, entry := range p.quarantine.Snapshot() {
		if entry.Kind == quarantineRateLimited {
			continue
		}
		if strings.HasPrefix(domain, "*.") {
			continue
		}
		if p.config.Unprobeable != nil && p.config.Unprobeable(domain) {
			continue
		}
		if !p.quarantine.IsQuarantined(domain) {
			continue
		}
		candidates = append(candidates, domain)
	}
	return candidates
}
