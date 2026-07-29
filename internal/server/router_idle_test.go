package server

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testIdleRouter(t *testing.T, lifecycle ContainerLifecycle) *Router {
	t.Helper()

	router := testRouter(t)
	router.SetContainerLifecycle(lifecycle)

	// Stop the controllers before t.TempDir is removed: a wake persists state from
	// its own goroutine, which otherwise races the cleanup and fails the test with
	// "directory not empty".
	t.Cleanup(func() {
		for _, service := range router.services.All() {
			service.Dispose()
		}
	})

	return router
}

func sleepingDeployOptions(t *testing.T) ServiceOptions {
	t.Helper()

	options := defaultServiceOptions
	options.Hosts = []string{"app.example.com"}
	options.SleepAfter = time.Hour
	// A test backend listens on 127.0.0.1, which ContainerRef rightly refuses as
	// an address rather than a container.
	options.SleepContainers = []string{"web-1"}
	return options
}

// Without a socket the proxy cannot ever act on --sleep-after. Accepting the
// deploy and discovering that at the first idle timeout leaves an operator
// believing a service sleeps when it never will.
func TestRouter_DeployRejectsSleepAfterWithoutAContainerRuntime(t *testing.T) {
	router := testRouter(t) // no lifecycle installed
	_, target := testBackend(t, "first", http.StatusOK)

	err := router.DeployService("sleepy", []string{target}, defaultEmptyReaders,
		sleepingDeployOptions(t), defaultTargetOptions, defaultDeploymentOptions)

	require.ErrorIs(t, err, ErrNoContainerLifecycle)
}

// The preflight turns a wrong container reference into an error on the
// operator's terminal instead of a 503 an hour later.
func TestRouter_DeployRejectsAnUnknownContainer(t *testing.T) {
	lifecycle := &fakeLifecycle{
		existsFunc: func(ctx context.Context, ref string) error { return ErrContainerNotFound },
	}
	router := testIdleRouter(t, lifecycle)
	_, target := testBackend(t, "first", http.StatusOK)

	err := router.DeployService("sleepy", []string{target}, defaultEmptyReaders,
		sleepingDeployOptions(t), defaultTargetOptions, defaultDeploymentOptions)

	require.ErrorIs(t, err, ErrNotAContainerRef)
	assert.ErrorContains(t, err, "--sleep-container",
		"the error has to say how to fix it")
}

// A hardened socket proxy commonly allows start and stop while denying inspect.
// Refusing the deploy for that would lock out exactly the operators doing the
// right thing.
func TestRouter_DeployWarnsButProceedsWhenInspectIsForbidden(t *testing.T) {
	lifecycle := &fakeLifecycle{
		existsFunc: func(ctx context.Context, ref string) error { return ErrContainerInspectForbidden },
	}
	router := testIdleRouter(t, lifecycle)
	_, target := testBackend(t, "first", http.StatusOK)

	err := router.DeployService("sleepy", []string{target}, defaultEmptyReaders,
		sleepingDeployOptions(t), defaultTargetOptions, defaultDeploymentOptions)

	assert.NoError(t, err)
}

func TestRouter_DeploySucceedsWithAKnownContainer(t *testing.T) {
	lifecycle := &fakeLifecycle{}
	router := testIdleRouter(t, lifecycle)
	_, target := testBackend(t, "first", http.StatusOK)

	require.NoError(t, router.DeployService("sleepy", []string{target}, defaultEmptyReaders,
		sleepingDeployOptions(t), defaultTargetOptions, defaultDeploymentOptions))

	service := router.serviceForName("sleepy")
	require.NotNil(t, service)
	require.NotNil(t, service.idleController, "the deployed service gets a controller")
}

// A deploy that does not ask for sleep must not need a socket at all.
func TestRouter_DeployWithoutSleepNeedsNoContainerRuntime(t *testing.T) {
	router := testRouter(t)
	_, target := testBackend(t, "first", http.StatusOK)

	require.NoError(t, router.DeployService("plain", []string{target}, defaultEmptyReaders,
		defaultServiceOptions, defaultTargetOptions, defaultDeploymentOptions))
}

// Sleeping has to survive a proxy restart, and the restored service's pool has to
// come back suspended: restore assumes every target healthy, which for a sleeping
// service is a healthy pool pointing at a stopped container.
func TestRouter_SleepingStateSurvivesARestart(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	lifecycle := &fakeLifecycle{}

	router := NewRouter(statePath)
	router.SetContainerLifecycle(lifecycle)
	_, target := testBackend(t, "first", http.StatusOK)

	require.NoError(t, router.DeployService("sleepy", []string{target}, defaultEmptyReaders,
		sleepingDeployOptions(t), defaultTargetOptions, defaultDeploymentOptions))

	service := router.serviceForName("sleepy")
	require.NotNil(t, service.idleController)

	// Sleep it, which must persist without anyone calling SaveState.
	service.idleController.RestoreSleeping()
	service.persistState()

	restored := NewRouter(statePath)
	require.NoError(t, restored.RestoreLastSavedState())
	restored.SetContainerLifecycle(lifecycle)

	restoredService := restored.serviceForName("sleepy")
	require.NotNil(t, restoredService)
	require.NotNil(t, restoredService.idleController,
		"SetContainerLifecycle builds the controller a restored service could not")
	assert.Equal(t, IdleStateSleeping, restoredService.idleController.State())
	assert.Empty(t, restoredService.active.HealthyTargets(),
		"a restored sleeping service must not route to its stopped container")
}

// The controller persists on the sleep and wake edges, which only works if the
// router actually handed the service a persister.
func TestRouter_SleepEdgeIsPersistedWithoutAnExplicitSave(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	router := NewRouter(statePath)
	router.SetContainerLifecycle(&fakeLifecycle{})
	_, target := testBackend(t, "first", http.StatusOK)

	require.NoError(t, router.DeployService("sleepy", []string{target}, defaultEmptyReaders,
		sleepingDeployOptions(t), defaultTargetOptions, defaultDeploymentOptions))

	service := router.serviceForName("sleepy")
	require.NotNil(t, service.statePersister,
		"without this the sleep/wake edges are never written and a restart forgets")

	service.persistState()

	reloaded := NewRouter(statePath)
	require.NoError(t, reloaded.RestoreLastSavedState())
	assert.NotNil(t, reloaded.serviceForName("sleepy"))
}

func TestRouter_ListShowsSleepingAndPrefersPaused(t *testing.T) {
	lifecycle := &fakeLifecycle{}
	router := testIdleRouter(t, lifecycle)
	_, target := testBackend(t, "first", http.StatusOK)

	require.NoError(t, router.DeployService("sleepy", []string{target}, defaultEmptyReaders,
		sleepingDeployOptions(t), defaultTargetOptions, defaultDeploymentOptions))

	service := router.serviceForName("sleepy")

	assert.Equal(t, "running", router.ListActiveServices()["sleepy"].State)

	service.idleController.RestoreSleeping()
	assert.Equal(t, "sleeping", router.ListActiveServices()["sleepy"].State)

	// A pause is a human decision and outranks anything traffic-driven.
	require.NoError(t, router.PauseService("sleepy", time.Second, time.Second))
	assert.Equal(t, "paused", router.ListActiveServices()["sleepy"].State)
}

// A cache hit never reaches the target, so it must not spend a container start.
// Serving stored responses while the container stays asleep is the whole point
// of running both features on one service.
func TestService_CacheHitDoesNotWakeASleepingService(t *testing.T) {
	lifecycle := &fakeLifecycle{}

	options := sleepingDeployOptions(t)
	options.Cache = CacheOptions{Enabled: true}

	var reached atomic.Int64
	_, target := testBackendWithHandler(t, countingHandler(&reached, publicHandler("cached")))

	router := testIdleRouter(t, lifecycle)
	router.SetCacheStore(testMemoryStore(t))
	require.NoError(t, router.DeployService("sleepy", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	// Warm the cache while awake.
	statusCode, _ := sendGETRequest(router, "http://app.example.com/")
	require.Equal(t, http.StatusOK, statusCode)
	require.Equal(t, int64(1), reached.Load())

	service := router.serviceForName("sleepy")
	require.NotNil(t, service.idleController)
	service.idleController.RestoreSleeping()

	statusCode, body := sendGETRequest(router, "http://app.example.com/")

	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, "cached", body)
	assert.Equal(t, int64(1), reached.Load(), "the response came from the cache")
	assert.Zero(t, lifecycle.starts.Load(), "a cache hit must not wake the containers")
	assert.Equal(t, IdleStateSleeping, service.idleController.State())
}

// The other half: a request the cache cannot serve still needs the target, so it
// has to wake.
func TestService_CacheMissWakesASleepingService(t *testing.T) {
	lifecycle := &fakeLifecycle{}

	options := sleepingDeployOptions(t)
	options.Cache = CacheOptions{Enabled: true}

	var reached atomic.Int64
	_, target := testBackendWithHandler(t, countingHandler(&reached, publicHandler("fresh")))

	router := testIdleRouter(t, lifecycle)
	router.SetCacheStore(testMemoryStore(t))
	require.NoError(t, router.DeployService("sleepy", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	service := router.serviceForName("sleepy")
	service.idleController.RestoreSleeping()

	statusCode, _ := sendGETRequest(router, "http://app.example.com/never-warmed")

	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, int64(1), lifecycle.starts.Load(), "a miss needs the target, so it wakes")
	assert.Equal(t, IdleStateActive, service.idleController.State())
}

func TestRouter_DeployReportsALifecycleFailure(t *testing.T) {
	lifecycle := &fakeLifecycle{
		existsFunc: func(ctx context.Context, ref string) error { return errors.New("socket is a directory") },
	}
	router := testIdleRouter(t, lifecycle)
	_, target := testBackend(t, "first", http.StatusOK)

	err := router.DeployService("sleepy", []string{target}, defaultEmptyReaders,
		sleepingDeployOptions(t), defaultTargetOptions, defaultDeploymentOptions)

	require.Error(t, err)
	assert.ErrorContains(t, err, "socket is a directory")
}
