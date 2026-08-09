package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDenyList_ParseErrors(t *testing.T) {
	tests := []struct {
		name           string
		denyIPs        []string
		denyUserAgents []string
		expectedError  string
	}{
		{
			name:          "invalid address",
			denyIPs:       []string{"not-an-ip"},
			expectedError: "deny-ip",
		},
		{
			name:          "invalid CIDR",
			denyIPs:       []string{"10.0.0.0/33"},
			expectedError: "deny-ip",
		},
		{
			name:          "empty address entry",
			denyIPs:       []string{""},
			expectedError: "deny-ip",
		},
		{
			name:           "invalid regex",
			denyUserAgents: []string{"BadBot("},
			expectedError:  "deny-user-agent",
		},
		{
			name:           "empty pattern",
			denyUserAgents: []string{""},
			expectedError:  "deny-user-agent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newDenyList(tt.denyIPs, tt.denyUserAgents, nil, "")

			require.ErrorIs(t, err, ErrServiceOptionsInvalid)
			require.ErrorContains(t, err, tt.expectedError)
		})
	}
}

func TestDenyList_DeniesAddr(t *testing.T) {
	list, err := newDenyList([]string{"203.0.113.0/24", "198.51.100.7", "2001:db8::1"}, nil, nil, "")
	require.NoError(t, err)

	tests := []struct {
		name   string
		addr   string
		denied bool
	}{
		{"address inside a denied range", "203.0.113.9", true},
		{"address outside every range", "10.0.0.5", false},
		{"exactly the denied address", "198.51.100.7", true},
		{"neighbour of the denied address", "198.51.100.8", false},
		{"exactly the denied IPv6 address", "2001:db8::1", true},
		{"same /64 as the denied IPv6 address", "2001:db8::2", false},
		{"IPv4-mapped form of a denied address", "::ffff:203.0.113.9", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.denied, list.deniesAddr(parseHostAddr(tt.addr)))
		})
	}
}

func TestDenyList_ZeroAddrMatchesNothing(t *testing.T) {
	// A deny names exactly what the operator wrote; an unresolvable client is
	// not any of those things. The allow list still refuses it when one is set.
	list, err := newDenyList([]string{"0.0.0.0/0", "::/0"}, nil, nil, "")
	require.NoError(t, err)

	assert.False(t, list.deniesAddr(parseHostAddr("not-an-address")))
}

func TestDenyList_DeniesUserAgent(t *testing.T) {
	list, err := newDenyList(nil, []string{`BadBot/.*`, `^$`, `(?i)evilcrawler`}, nil, "")
	require.NoError(t, err)

	tests := []struct {
		name      string
		userAgent string
		denied    bool
	}{
		{"full match on the pattern", "BadBot/1.0", true},
		{"different agent", "GoodBot/1.0", false},
		{"pattern is anchored, prefix junk escapes it", "xBadBot/1.0", false},
		{"pattern is anchored, matching only a substring is not enough", "EvilCrawler plus trailing junk", false},
		{"case-insensitive when the pattern says so", "eViLcRaWlEr", true},
		{"missing agent matches the explicit empty pattern", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.denied, list.deniesUserAgent(tt.userAgent))
		})
	}
}

func TestDenyList_MissingUserAgentIsNotACrime(t *testing.T) {
	// .* matches the empty string, but absence only matches an explicit ^$.
	list, err := newDenyList(nil, []string{`.*`}, nil, "")
	require.NoError(t, err)

	assert.False(t, list.deniesUserAgent(""))
	assert.True(t, list.deniesUserAgent("anything at all"))
}

func TestDenyList_ValidateDeny(t *testing.T) {
	tests := []struct {
		name          string
		options       ServiceOptions
		expectedError string
	}{
		{
			name:    "deny-ip alone is valid",
			options: ServiceOptions{DenyIPs: []string{"203.0.113.0/24"}},
		},
		{
			name:    "deny-user-agent alone is valid",
			options: ServiceOptions{DenyUserAgents: []string{`BadBot/.*`}},
		},
		{
			name:    "deny-ip justifies trusted-proxy on its own",
			options: ServiceOptions{DenyIPs: []string{"203.0.113.0/24"}, TrustedProxies: []string{"10.0.0.0/8"}},
		},
		{
			name:          "trusted-proxy still needs a consumer",
			options:       ServiceOptions{TrustedProxies: []string{"10.0.0.0/8"}},
			expectedError: "trusted-proxy requires",
		},
		{
			name:          "deny-ip with client-ip-header requires trusted-proxy",
			options:       ServiceOptions{DenyIPs: []string{"203.0.113.0/24"}, ClientIPHeader: "CF-Connecting-IP"},
			expectedError: "requires trusted-proxy",
		},
		{
			name:          "invalid deny-ip entry",
			options:       ServiceOptions{DenyIPs: []string{"not-an-ip"}},
			expectedError: "deny-ip",
		},
		{
			name:          "invalid deny-user-agent entry",
			options:       ServiceOptions{DenyUserAgents: []string{"("}},
			expectedError: "deny-user-agent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.options.Validate()

			if tt.expectedError == "" {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrServiceOptionsInvalid)
				require.ErrorContains(t, err, tt.expectedError)
			}
		})
	}
}

func TestDenyList_ValidateDenyHealthCheck(t *testing.T) {
	tests := []struct {
		name        string
		options     ServiceOptions
		path        string
		expectError bool
	}{
		{
			name:        "deny-ip with a root health check path",
			options:     ServiceOptions{DenyIPs: []string{"203.0.113.0/24"}},
			path:        "/",
			expectError: true,
		},
		{
			name:        "deny-user-agent with a root health check path",
			options:     ServiceOptions{DenyUserAgents: []string{`BadBot/.*`}},
			path:        "/",
			expectError: true,
		},
		{
			name:    "deny rules with a dedicated health check path",
			options: ServiceOptions{DenyIPs: []string{"203.0.113.0/24"}},
			path:    "/up",
		},
		{
			name:    "no deny rules with a root health check path",
			options: ServiceOptions{},
			path:    "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targetOptions := defaultTargetOptions
			targetOptions.HealthCheckConfig.Path = tt.path

			err := validateDenyHealthCheck(tt.options, targetOptions)

			if tt.expectError {
				require.ErrorIs(t, err, ErrServiceOptionsInvalid)
				require.ErrorContains(t, err, "health-check-path")
			} else {
				require.NoError(t, err)
			}
		})
	}
}
