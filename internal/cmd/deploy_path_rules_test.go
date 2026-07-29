package cmd

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/basecamp/kamal-proxy/internal/server"
)

// A separate file from deploy_test.go, which is already near the size the
// coding style caps a file at.

func TestDeployCommand_PathRuleFlags(t *testing.T) {
	tests := []struct {
		name             string
		args             []string
		expectedError    string
		expectedRedirect []server.PathRule
		expectedRewrite  []server.PathRule
	}{
		{
			name: "unset leaves both empty",
			args: []string{"--target=web:3000"},
		},
		{
			name: "a redirect defaults to a permanent one",
			args: []string{"--target=web:3000", "--redirect=/old=/new"},
			expectedRedirect: []server.PathRule{
				{Pattern: "/old", Replacement: "/new"},
			},
		},
		{
			name: "repeating a flag accumulates in the order given",
			args: []string{
				"--target=web:3000",
				"--redirect=/blog/(.*)=/news/$1",
				"--redirect=/gone=https://elsewhere.example.com/;status=302",
			},
			expectedRedirect: []server.PathRule{
				{Pattern: "/blog/(.*)", Replacement: "/news/$1"},
				{Pattern: "/gone", Replacement: "https://elsewhere.example.com/", Status: http.StatusFound},
			},
		},
		{
			name: "a comma in a pattern stays part of the pattern",
			args: []string{"--target=web:3000", "--redirect=/x/(a,b)=/y/$1"},
			expectedRedirect: []server.PathRule{
				{Pattern: "/x/(a,b)", Replacement: "/y/$1"},
			},
		},
		{
			name: "a rewrite serves an SPA's own routes",
			args: []string{"--target=web:3000", "--rewrite=/[^.]*=/index.html"},
			expectedRewrite: []server.PathRule{
				{Pattern: "/[^.]*", Replacement: "/index.html"},
			},
		},
		{
			name:          "a rule without a separator is rejected",
			args:          []string{"--target=web:3000", "--redirect=/old"},
			expectedError: `redirect must be given as "<pattern>=<replacement>"`,
		},
		{
			name:          "an unparseable pattern is rejected before deploying",
			args:          []string{"--target=web:3000", "--redirect=/old(=/new"},
			expectedError: "redirect has an invalid pattern",
		},
		{
			name:          "a status that is not a redirect is rejected",
			args:          []string{"--target=web:3000", "--redirect=/old=/new;status=404"},
			expectedError: "redirect status must be one of 301, 302, 303, 307, 308",
		},
		{
			name:          "a rewrite cannot send the client elsewhere",
			args:          []string{"--target=web:3000", "--rewrite=/old=https://elsewhere.example.com/"},
			expectedError: "rewrite replacement must be an absolute path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newDeployCommand()
			require.NoError(t, cmd.cmd.Flags().Parse(tt.args))

			err := cmd.preRun(cmd.cmd, []string{"test-service"})

			if tt.expectedError != "" {
				require.ErrorIs(t, err, server.ErrServiceOptionsInvalid)
				require.ErrorContains(t, err, tt.expectedError)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedRedirect, cmd.args.ServiceOptions.Redirects)
			assert.Equal(t, tt.expectedRewrite, cmd.args.ServiceOptions.Rewrites)
		})
	}
}
