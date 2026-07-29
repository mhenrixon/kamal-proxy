package server

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

const (
	// DefaultTargetWeight is the share a target takes when its spec carries no
	// weight, and the share every target had before weights existed. A pool where
	// nothing deviates from it round-robins exactly as it always did.
	DefaultTargetWeight = 1

	// MaxTargetWeight bounds a single target's share. No canary split needs finer
	// resolution than 1:1000, and the cap keeps the selection credits, which
	// accumulate by weight, well clear of overflow.
	MaxTargetWeight = 1000

	targetAttributeSeparator = ";"
	targetWeightAttribute    = "weight="
)

var ErrorInvalidTargetWeight = errors.New("invalid target weight")

// parseTargetSpec splits a deploy-time target spec into the host to proxy to and
// the share of traffic it should take, as `host[:port][;weight=n]`. The host is
// returned unvalidated: parseTargetURL owns what a host may look like.
func parseTargetSpec(spec string) (string, int, error) {
	host, attribute, found := strings.Cut(spec, targetAttributeSeparator)
	if !found {
		return spec, DefaultTargetWeight, nil
	}

	value, ok := strings.CutPrefix(attribute, targetWeightAttribute)
	if !ok {
		return "", 0, fmt.Errorf("%w: '%s' is not a target attribute, expected '%sN'", ErrorInvalidTargetWeight, attribute, targetWeightAttribute)
	}

	weight, err := strconv.Atoi(value)
	if err != nil {
		return "", 0, fmt.Errorf("%w: '%s' is not a whole number", ErrorInvalidTargetWeight, value)
	}

	if weight < DefaultTargetWeight || weight > MaxTargetWeight {
		return "", 0, fmt.Errorf("%w: %d is outside %d-%d", ErrorInvalidTargetWeight, weight, DefaultTargetWeight, MaxTargetWeight)
	}

	return host, weight, nil
}

// Weight is the share of its pool's traffic this target takes, relative to the
// other healthy targets in that pool.
func (t *Target) Weight() int {
	return t.weight
}

// Spec renders the target back into the form it was deployed as, so that a
// weight survives a restart. A default weight is left off: an unweighted
// deployment then writes the state file it has always written, which a proxy
// build predating weights can still read.
func (t *Target) Spec() string {
	if t.weight == DefaultTargetWeight {
		return t.Address()
	}

	return t.Address() + targetAttributeSeparator + targetWeightAttribute + strconv.Itoa(t.weight)
}

// Specs returns the deploy-time form of each target, weights included. This is
// what belongs in persisted state; Names, which drops the weight, is what
// belongs anywhere an address is what's meant.
func (tl TargetList) Specs() []string {
	specs := make([]string, 0, len(tl))
	for _, target := range tl {
		specs = append(specs, target.Spec())
	}
	return specs
}

func (tl TargetList) hasWeights() bool {
	return slices.ContainsFunc(tl, func(target *Target) bool {
		return target.weight != DefaultTargetWeight
	})
}

// nextWeighted picks the target to serve the next request using nginx's smooth
// weighted round-robin: every target's credit grows by its weight, the one
// holding the most credit serves and pays back the pool's total. Across a full
// cycle each target has served exactly its weight, with the turns interleaved
// rather than served in runs -- a 1:5 split alternates instead of sending five
// consecutive requests to the heavy target.
//
// The credits are mutable per-target state, so the caller must hold the lock
// guarding the pool. LoadBalancer.nextTarget is called under its own lock, and
// nothing else reaches these fields.
func (tl TargetList) nextWeighted() *Target {
	var chosen *Target
	total := 0

	for _, target := range tl {
		target.currentWeight += target.weight
		total += target.weight

		if chosen == nil || target.currentWeight > chosen.currentWeight {
			chosen = target
		}
	}

	if chosen == nil {
		return nil
	}

	chosen.currentWeight -= total
	return chosen
}
