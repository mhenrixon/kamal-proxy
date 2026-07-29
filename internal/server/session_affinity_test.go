package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionAffinity_PinsRepeatedRequestsToOneTarget(t *testing.T) {
	lb := testPinningLoadBalancer(t, SessionAffinityPolicy{Enabled: true},
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("one")) },
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("two")) },
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("three")) },
	)
	require.NoError(t, lb.WaitUntilHealthy(time.Second))

	first := sendPinnedRequest(t, lb, nil)
	cookie := sessionAffinityCookie(t, first)
	require.NotNil(t, cookie, "the first response must pin the client")

	for range 6 {
		w := sendPinnedRequest(t, lb, cookie)
		assert.Equal(t, first.Body.String(), w.Body.String())
	}
}

func TestSessionAffinity_PinCookieIsIssuedOnlyOnce(t *testing.T) {
	lb := testPinningLoadBalancer(t, SessionAffinityPolicy{Enabled: true},
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("one")) },
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("two")) },
	)
	require.NoError(t, lb.WaitUntilHealthy(time.Second))

	cookie := sessionAffinityCookie(t, sendPinnedRequest(t, lb, nil))
	require.NotNil(t, cookie)

	w := sendPinnedRequest(t, lb, cookie)
	assert.Nil(t, sessionAffinityCookie(t, w), "a request already on its pinned target should not be re-pinned")
}

func TestSessionAffinity_CookieAttributes(t *testing.T) {
	lb := testPinningLoadBalancer(t, SessionAffinityPolicy{Enabled: true},
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("one")) },
	)
	require.NoError(t, lb.WaitUntilHealthy(time.Second))

	cookie := sessionAffinityCookie(t, sendPinnedRequest(t, lb, nil))
	require.NotNil(t, cookie)

	assert.Equal(t, DefaultSessionAffinityCookieName, cookie.Name)
	assert.Equal(t, "/", cookie.Path)
	assert.True(t, cookie.HttpOnly)
	assert.False(t, cookie.Secure, "a plain HTTP request must not get a Secure cookie it will never send back")
	assert.True(t, cookie.Expires.IsZero(), "the pin lasts for the browser session, not a fixed window")
}

// The cookie names the target obliquely: anyone holding one must not be able to
// read the proxy's internal topology out of it, or confirm a guessed address.
func TestSessionAffinity_CookieValueDoesNotLeakTheTargetAddress(t *testing.T) {
	lb := testPinningLoadBalancer(t, SessionAffinityPolicy{Enabled: true},
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("one")) },
	)
	require.NoError(t, lb.WaitUntilHealthy(time.Second))

	address := lb.Targets()[0].Address()
	cookie := sessionAffinityCookie(t, sendPinnedRequest(t, lb, nil))
	require.NotNil(t, cookie)

	assert.NotContains(t, cookie.Value, address)
	host, _, _ := strings.Cut(address, ":")
	assert.NotContains(t, cookie.Value, host)

	// Two load balancers over the same address must not agree on the pin, or the
	// value would be a plain hash anyone could recompute from a guessed address.
	other := NewLoadBalancer(lb.Targets(), DefaultWriterAffinityTimeout, false).
		WithSessionAffinity(SessionAffinityPolicy{Enabled: true})
	t.Cleanup(other.Dispose)

	assert.NotEqual(t, cookie.Value, other.sessionAffinity.ids[lb.Targets()[0]])
}

func TestSessionAffinity_RepinsWhenPinnedTargetIsUnhealthy(t *testing.T) {
	lb := testPinningLoadBalancer(t, SessionAffinityPolicy{Enabled: true},
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("one")) },
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("two")) },
	)
	require.NoError(t, lb.WaitUntilHealthy(time.Second))

	first := sendPinnedRequest(t, lb, nil)
	cookie := sessionAffinityCookie(t, first)
	require.NotNil(t, cookie)

	pinned := targetServing(t, lb, first.Body.String())
	pinned.updateState(TargetStateUnhealthy)
	lb.updateHealthyTargets()

	w := sendPinnedRequest(t, lb, cookie)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEqual(t, first.Body.String(), w.Body.String(), "the request must fall through to a healthy target")

	reissued := sessionAffinityCookie(t, w)
	require.NotNil(t, reissued, "a stale pin must be replaced, not left pointing at a dead target")
	assert.NotEqual(t, cookie.Value, reissued.Value)
}

func TestSessionAffinity_IgnoresAnUnknownPin(t *testing.T) {
	lb := testPinningLoadBalancer(t, SessionAffinityPolicy{Enabled: true},
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("one")) },
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("two")) },
	)
	require.NoError(t, lb.WaitUntilHealthy(time.Second))

	w := sendPinnedRequest(t, lb, &http.Cookie{Name: DefaultSessionAffinityCookieName, Value: "not-a-real-pin"})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotNil(t, sessionAffinityCookie(t, w))
}

func TestSessionAffinity_UsesACustomCookieName(t *testing.T) {
	lb := testPinningLoadBalancer(t, SessionAffinityPolicy{Enabled: true, CookieName: "app-instance"},
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("one")) },
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("two")) },
	)
	require.NoError(t, lb.WaitUntilHealthy(time.Second))

	first := sendPinnedRequest(t, lb, nil)
	cookies := first.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, "app-instance", cookies[0].Name)

	for range 4 {
		w := sendPinnedRequest(t, lb, cookies[0])
		assert.Equal(t, first.Body.String(), w.Body.String())
	}
}

// Default off: a deployment that does not ask for affinity must behave exactly
// as it did before the option existed.
func TestSessionAffinity_DisabledLeavesSelectionUntouched(t *testing.T) {
	lb := testLoadBalancerWithHandlers(t,
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("one")) },
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("two")) },
	)
	require.NoError(t, lb.WaitUntilHealthy(time.Second))

	bodies := map[string]bool{}
	for range 4 {
		w := sendPinnedRequest(t, lb, nil)
		assert.Empty(t, w.Result().Cookies())
		bodies[w.Body.String()] = true
	}

	assert.Len(t, bodies, 2, "both targets should still take a share")
}

// Read replicas hold no per-instance session state, so a read served by one is
// not pinned. Writes still are, and the writer-affinity cookie then keeps a
// client's reads on its pinned writer for the window after a write.
func TestSessionAffinity_DoesNotPinReadsServedByReaders(t *testing.T) {
	writer := testTarget(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("writer")) })
	reader := testReadOnlyTarget(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("reader")) })

	tl, err := NewTargetList([]string{writer.Address()}, []string{reader.Address()}, defaultTargetOptions)
	require.NoError(t, err)

	lb := NewLoadBalancer(tl, DefaultWriterAffinityTimeout, false).
		WithSessionAffinity(SessionAffinityPolicy{Enabled: true})
	t.Cleanup(lb.Dispose)
	require.NoError(t, lb.WaitUntilHealthy(time.Second))

	read := httptest.NewRecorder()
	lb.StartRequest(read, httptest.NewRequest(http.MethodGet, "/", nil))()
	assert.Equal(t, "reader", read.Body.String())
	assert.Nil(t, sessionAffinityCookie(t, read))

	write := httptest.NewRecorder()
	lb.StartRequest(write, httptest.NewRequest(http.MethodPost, "/", nil))()
	assert.Equal(t, "writer", write.Body.String())
	assert.NotNil(t, sessionAffinityCookie(t, write), "writes must still pin")
}

// A pin must not defeat retries: a target that is in the pool but cannot serve
// still has to be retried past, exactly as an unpinned request would be.
func TestSessionAffinity_RetriesPastAPinnedTargetThatCannotServe(t *testing.T) {
	lb := testPinningLoadBalancer(t, SessionAffinityPolicy{Enabled: true},
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("one")) },
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("two")) },
	)
	lb.WithRetryPolicy(RetryPolicy{TryDuration: time.Second})
	require.NoError(t, lb.WaitUntilHealthy(time.Second))

	first := sendPinnedRequest(t, lb, nil)
	cookie := sessionAffinityCookie(t, first)
	require.NotNil(t, cookie)

	// Draining leaves the target in the pool, so only the retry loop can get the
	// request off it.
	targetServing(t, lb, first.Body.String()).updateState(TargetStateDraining)

	w := sendPinnedRequest(t, lb, cookie)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEqual(t, first.Body.String(), w.Body.String())
}

// Giving up must not hand back a pin: the client would come straight back to
// the target the proxy just gave up on.
func TestSessionAffinity_DoesNotPinWhenEveryTargetFails(t *testing.T) {
	dead, deadURL := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {})
	dead.Close()

	tl, err := NewTargetList([]string{deadURL}, []string{}, defaultTargetOptions)
	require.NoError(t, err)

	lb := NewLoadBalancer(tl, DefaultWriterAffinityTimeout, false).
		WithSessionAffinity(SessionAffinityPolicy{Enabled: true}).
		WithRetryPolicy(RetryPolicy{TryDuration: time.Millisecond * 50})
	t.Cleanup(lb.Dispose)
	lb.MarkAllHealthy()

	w := sendPinnedRequest(t, lb, nil)

	assert.NotEqual(t, http.StatusOK, w.Code)
	assert.Nil(t, sessionAffinityCookie(t, w))
}

func TestServiceOptions_ValidateSessionAffinity(t *testing.T) {
	tests := []struct {
		name        string
		enabled     bool
		cookieName  string
		expectedErr string
	}{
		{"off by default", false, "", ""},
		{"enabled with the default cookie", true, "", ""},
		{"enabled with a custom cookie", true, "app-instance", ""},
		{"cookie name without the option", false, "app-instance", "session-affinity-cookie requires session-affinity"},
		{"cookie name with a space", true, "app instance", "not a valid cookie name"},
		{"cookie name with a separator", true, "app;instance", "not a valid cookie name"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := ServiceOptions{SessionAffinity: tt.enabled, SessionAffinityCookieName: tt.cookieName}

			err := options.Validate()
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrServiceOptionsInvalid)
				assert.Contains(t, err.Error(), tt.expectedErr)
			}
		})
	}
}

// BenchmarkSessionAffinity_ClaimPinnedTarget is the same selection as
// BenchmarkLoadBalancer_ClaimTarget, paying for the pin lookup: read the
// cookie, then compare identifiers down the healthy pool.
func BenchmarkSessionAffinity_ClaimPinnedTarget(b *testing.B) {
	lb := benchmarkLoadBalancer(b).WithSessionAffinity(SessionAffinityPolicy{Enabled: true})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  DefaultSessionAffinityCookieName,
		Value: lb.sessionAffinity.ids[lb.Targets()[len(lb.Targets())-1]],
	})

	b.ReportAllocs()
	for b.Loop() {
		target, claimed, _, err := lb.claimTarget(req)
		if err != nil {
			b.Fatal(err)
		}
		target.endInflightRequest(claimed)
	}
}

// Helpers

func testPinningLoadBalancer(t *testing.T, policy SessionAffinityPolicy, handlers ...http.HandlerFunc) *LoadBalancer {
	t.Helper()

	targets := []string{}
	for _, h := range handlers {
		targets = append(targets, testTarget(t, h).Address())
	}

	tl, err := NewTargetList(targets, []string{}, defaultTargetOptions)
	require.NoError(t, err)

	lb := NewLoadBalancer(tl, DefaultWriterAffinityTimeout, false).WithSessionAffinity(policy)
	t.Cleanup(lb.Dispose)

	return lb
}

func sendPinnedRequest(t *testing.T, lb *LoadBalancer, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}

	w := httptest.NewRecorder()
	lb.StartRequest(w, req)()

	return w
}

func sessionAffinityCookie(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()

	for _, cookie := range w.Result().Cookies() {
		if cookie.Name != LoadBalancerWriteCookieName {
			return cookie
		}
	}

	return nil
}

// targetServing finds the target behind a response body, so a test can act on
// the one the load balancer actually picked.
func targetServing(t *testing.T, lb *LoadBalancer, body string) *Target {
	t.Helper()

	for _, target := range lb.Targets() {
		w := httptest.NewRecorder()
		req, err := target.StartRequest(httptest.NewRequest(http.MethodGet, "/", nil))
		require.NoError(t, err)
		target.SendRequest(w, req)

		if w.Body.String() == body {
			return target
		}
	}

	require.FailNow(t, "no target served "+body)
	return nil
}
