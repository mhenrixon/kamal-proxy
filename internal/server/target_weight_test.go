package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTargetSpec(t *testing.T) {
	tests := []struct {
		name           string
		spec           string
		expectedHost   string
		expectedWeight int
		expectError    bool
	}{
		{name: "bare host", spec: "web", expectedHost: "web", expectedWeight: DefaultTargetWeight},
		{name: "host with port", spec: "web:3000", expectedHost: "web:3000", expectedWeight: DefaultTargetWeight},
		{name: "explicit weight", spec: "web:3000;weight=5", expectedHost: "web:3000", expectedWeight: 5},
		{name: "weight of one", spec: "web;weight=1", expectedHost: "web", expectedWeight: 1},
		{name: "maximum weight", spec: "web;weight=1000", expectedHost: "web", expectedWeight: MaxTargetWeight},
		{name: "zero weight", spec: "web;weight=0", expectError: true},
		{name: "negative weight", spec: "web;weight=-1", expectError: true},
		{name: "weight above maximum", spec: "web;weight=1001", expectError: true},
		{name: "non-numeric weight", spec: "web;weight=heavy", expectError: true},
		{name: "empty weight", spec: "web;weight=", expectError: true},
		{name: "repeated attribute", spec: "web;weight=1;weight=2", expectError: true},
		{name: "unknown attribute", spec: "web;priority=2", expectError: true},
		{name: "trailing separator", spec: "web;", expectError: true},

		// The host is whatever precedes the attribute; parseTargetURL is what
		// decides whether it is one. TestTarget_MissingHostIsRejected covers it.
		{name: "attribute without host", spec: ";weight=2", expectedHost: "", expectedWeight: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, weight, err := parseTargetSpec(tt.spec)

			if tt.expectError {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrorInvalidTargetWeight)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedHost, host)
			assert.Equal(t, tt.expectedWeight, weight)
		})
	}
}

func TestTarget_WeightFromSpec(t *testing.T) {
	target, err := NewTarget("web:3000;weight=7", TargetOptions{})
	require.NoError(t, err)

	assert.Equal(t, "web:3000", target.Address())
	assert.Equal(t, 7, target.Weight())
}

func TestTarget_DefaultWeight(t *testing.T) {
	target, err := NewTarget("web:3000", TargetOptions{})
	require.NoError(t, err)

	assert.Equal(t, DefaultTargetWeight, target.Weight())
}

func TestTarget_ReadOnlyTargetsCarryWeights(t *testing.T) {
	target, err := NewReadOnlyTarget("replica:3000;weight=3", TargetOptions{})
	require.NoError(t, err)

	assert.True(t, target.ReadOnly())
	assert.Equal(t, "replica:3000", target.Address())
	assert.Equal(t, 3, target.Weight())
}

func TestTarget_InvalidWeightIsRejected(t *testing.T) {
	_, err := NewTarget("web:3000;weight=0", TargetOptions{})
	assert.ErrorIs(t, err, ErrorInvalidTargetWeight)
}

func TestTarget_InvalidHostIsStillRejectedWithAWeight(t *testing.T) {
	_, err := NewTarget("not a host;weight=2", TargetOptions{})
	assert.ErrorIs(t, err, ErrorInvalidHostPattern)
}

func TestTarget_MissingHostIsRejected(t *testing.T) {
	_, err := NewTarget(";weight=2", TargetOptions{})
	assert.ErrorIs(t, err, ErrorInvalidHostPattern)
}

// Specs is what reaches the state file, so an unweighted deployment has to keep
// writing bare hostnames: the file must stay loadable by a proxy that predates
// weights, and identical to what that proxy would have written.
func TestTargetList_Specs(t *testing.T) {
	tl, err := NewTargetList([]string{"one", "two;weight=3"}, []string{"three;weight=2"}, TargetOptions{})
	require.NoError(t, err)

	assert.Equal(t, []string{"one", "two", "three"}, tl.Names())
	assert.Equal(t, []string{"one", "two;weight=3", "three;weight=2"}, tl.Specs())
}

func TestTargetList_SpecsRoundTrip(t *testing.T) {
	tl, err := NewTargetList([]string{"one;weight=4", "two"}, []string{}, TargetOptions{})
	require.NoError(t, err)

	restored, err := NewTargetList(tl.Specs(), []string{}, TargetOptions{})
	require.NoError(t, err)

	assert.Equal(t, tl.Specs(), restored.Specs())
	assert.Equal(t, 4, restored[0].Weight())
	assert.Equal(t, DefaultTargetWeight, restored[1].Weight())
}

func TestTargetList_HasWeights(t *testing.T) {
	unweighted, err := NewTargetList([]string{"one", "two"}, []string{}, TargetOptions{})
	require.NoError(t, err)
	assert.False(t, unweighted.hasWeights())

	explicitDefaults, err := NewTargetList([]string{"one;weight=1", "two;weight=1"}, []string{}, TargetOptions{})
	require.NoError(t, err)
	assert.False(t, explicitDefaults.hasWeights())

	weighted, err := NewTargetList([]string{"one", "two;weight=2"}, []string{}, TargetOptions{})
	require.NoError(t, err)
	assert.True(t, weighted.hasWeights())
}

// The sequence is what separates weighted round-robin from "serve the heavy
// target N times, then the light one": both hit the same ratio, only one of them
// keeps the canary's share spread across the cycle.
func TestTargetList_WeightedSelectionIsSmooth(t *testing.T) {
	tl, err := NewTargetList([]string{"one;weight=1", "two;weight=2", "three;weight=3"}, []string{}, TargetOptions{})
	require.NoError(t, err)

	picked := []string{}
	for range 6 {
		picked = append(picked, tl.nextWeighted().Address())
	}

	assert.Equal(t, []string{"three", "two", "one", "three", "two", "three"}, picked)
}

func TestTargetList_WeightedSelectionMatchesTheWeights(t *testing.T) {
	tl, err := NewTargetList([]string{"light;weight=1", "heavy;weight=5"}, []string{}, TargetOptions{})
	require.NoError(t, err)

	counts := map[string]int{}
	for range 600 {
		counts[tl.nextWeighted().Address()]++
	}

	assert.Equal(t, map[string]int{"light": 100, "heavy": 500}, counts)
}

func TestTargetList_WeightedSelectionOverASingleTarget(t *testing.T) {
	tl, err := NewTargetList([]string{"only;weight=9"}, []string{}, TargetOptions{})
	require.NoError(t, err)

	for range 3 {
		assert.Equal(t, "only", tl.nextWeighted().Address())
	}
}

func TestLoadBalancer_WeightedTargetsSplitTraffic(t *testing.T) {
	lb := testWeightedLoadBalancer(t, map[string]int{"light": 1, "heavy": 3})
	require.NoError(t, lb.WaitUntilHealthy(time.Second))

	assert.Equal(t, map[string]int{"light": 2, "heavy": 6}, collectResponses(t, lb, "POST", 8))
}

// The unweighted path has to stay exactly what it was: same targets, same order,
// same starting point. A weighted pool is opt-in per deployment.
func TestLoadBalancer_UnweightedSelectionIsUnchanged(t *testing.T) {
	lb := testLoadBalancerWithHandlers(t,
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("one")) },
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("two")) },
	)
	require.NoError(t, lb.WaitUntilHealthy(time.Second))

	bodies := []string{}
	for range 4 {
		w := httptest.NewRecorder()
		lb.StartRequest(w, httptest.NewRequest("POST", "/", nil))()
		bodies = append(bodies, w.Body.String())
	}

	assert.Equal(t, []string{"two", "one", "two", "one"}, bodies)
}

// A weight only decides how a target's share compares to its healthy peers'. It
// must not keep an unhealthy target in the rotation, nor shrink the pool's total
// throughput when one drops out.
func TestLoadBalancer_WeightedSelectionSkipsUnhealthyTargets(t *testing.T) {
	targets := TargetList{
		testWeightedTarget(t, "light", 1, http.StatusOK),
		testWeightedTarget(t, "broken", 6, http.StatusInternalServerError),
		testWeightedTarget(t, "heavy", 3, http.StatusOK),
	}

	lb := NewLoadBalancer(targets, DefaultWriterAffinityTimeout, false)
	t.Cleanup(lb.Dispose)

	require.Eventually(t, func() bool {
		return len(lb.HealthyTargets()) == 2
	}, time.Second*5, time.Millisecond*10)

	assert.Equal(t, map[string]int{"light": 2, "heavy": 6}, collectResponses(t, lb, "POST", 8))
}

// Readers and writers rotate on separate cursors, so their weights have to be
// applied against their own pool rather than the combined target list.
func TestLoadBalancer_WeightedReadersAreIndependentOfWriters(t *testing.T) {
	_, writerURL := testBackend(t, "writer", http.StatusOK)
	_, lightURL := testBackend(t, "light", http.StatusOK)
	_, heavyURL := testBackend(t, "heavy", http.StatusOK)

	tl, err := NewTargetList(
		[]string{writerURL},
		[]string{lightURL + ";weight=1", heavyURL + ";weight=3"},
		defaultTargetOptions,
	)
	require.NoError(t, err)

	lb := NewLoadBalancer(tl, 0, false)
	t.Cleanup(lb.Dispose)
	require.NoError(t, lb.WaitUntilHealthy(time.Second))

	assert.Equal(t, map[string]int{"light": 2, "heavy": 6}, collectResponses(t, lb, "GET", 8))
	assert.Equal(t, map[string]int{"writer": 4}, collectResponses(t, lb, "POST", 4))
}

func TestService_StateFileRoundTripsWeights(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")

	_, light := testBackend(t, "light", http.StatusOK)
	_, heavy := testBackend(t, "heavy", http.StatusOK)
	_, reader := testBackend(t, "reader", http.StatusOK)

	router := NewRouter(statePath)
	require.NoError(t, router.DeployService("weighted",
		[]string{light, heavy + ";weight=3"},
		[]string{reader + ";weight=2"},
		defaultServiceOptions, defaultTargetOptions, defaultDeploymentOptions))

	restored := NewRouter(statePath)
	require.NoError(t, restored.RestoreLastSavedState())

	lb := restored.ListActiveServices()
	require.Contains(t, lb, "weighted")
	assert.Equal(t, []string{light, heavy}, lb["weighted"].Targets)
	assert.Equal(t, []string{reader}, lb["weighted"].ReaderTargets)

	weights := map[string]int{}
	for _, target := range restored.serviceForName("weighted").active.Targets() {
		weights[target.Address()] = target.Weight()
	}
	assert.Equal(t, map[string]int{light: 1, heavy: 3, reader: 2}, weights)
}

// An unweighted deployment must keep writing what it always wrote, so that a
// state file stays readable by a proxy build that predates weights.
func TestService_UnweightedStateFileIsUnchanged(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")

	_, target := testBackend(t, "target", http.StatusOK)

	router := NewRouter(statePath)
	require.NoError(t, router.DeployService("plain", []string{target}, defaultEmptyReaders,
		defaultServiceOptions, defaultTargetOptions, defaultDeploymentOptions))

	state, err := os.ReadFile(statePath)
	require.NoError(t, err)
	assert.NotContains(t, string(state), "weight=")
}

func TestRouter_RejectsInvalidTargetWeight(t *testing.T) {
	router := testRouter(t)
	_, target := testBackend(t, "target", http.StatusOK)

	err := router.DeployService("weighted", []string{target + ";weight=0"}, defaultEmptyReaders,
		defaultServiceOptions, defaultTargetOptions, defaultDeploymentOptions)

	assert.ErrorIs(t, err, ErrorInvalidTargetWeight)
}

// Helpers

func testWeightedTarget(t *testing.T, body string, weight int, statusCode int) *Target {
	t.Helper()

	_, targetURL := testBackend(t, body, statusCode)

	target, err := NewTarget(fmt.Sprintf("%s;weight=%d", targetURL, weight), defaultTargetOptions)
	require.NoError(t, err)

	return target
}

func testWeightedLoadBalancer(t *testing.T, weights map[string]int) *LoadBalancer {
	t.Helper()

	targets := []string{}
	for body, weight := range weights {
		_, targetURL := testBackend(t, body, http.StatusOK)
		targets = append(targets, fmt.Sprintf("%s;weight=%d", targetURL, weight))
	}

	tl, err := NewTargetList(targets, []string{}, defaultTargetOptions)
	require.NoError(t, err)

	lb := NewLoadBalancer(tl, DefaultWriterAffinityTimeout, false)
	t.Cleanup(lb.Dispose)

	return lb
}

func collectResponses(t *testing.T, lb *LoadBalancer, method string, count int) map[string]int {
	t.Helper()

	bodies := map[string]int{}
	for range count {
		w := httptest.NewRecorder()
		lb.StartRequest(w, httptest.NewRequest(method, "/", nil))()

		require.Equal(t, http.StatusOK, w.Code)
		bodies[w.Body.String()]++
	}

	return bodies
}
