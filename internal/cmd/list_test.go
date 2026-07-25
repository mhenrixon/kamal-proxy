package cmd

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/basecamp/kamal-proxy/internal/server"
)

func TestListCommand_JSONFlag(t *testing.T) {
	cmd := newListCommand().cmd

	flag := cmd.Flags().Lookup("json")
	require.NotNil(t, flag)
	assert.Equal(t, "false", flag.DefValue)
}

func TestListCommand_JSONOutputShape(t *testing.T) {
	response := server.ListResponse{
		Targets: server.ServiceDescriptionMap{
			"service1": {
				Host:           "example.com",
				Path:           "/",
				TLS:            true,
				Target:         "172.18.0.4:3000",
				State:          "running",
				Hosts:          []string{"example.com"},
				Targets:        []string{"172.18.0.4:3000"},
				ReaderTargets:  []string{"172.18.0.5:3000"},
				RolloutTargets: []string{"172.18.0.6:3000"},
			},
		},
	}

	data, err := json.Marshal(response)
	require.NoError(t, err)

	var decoded map[string]map[string]map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))

	service := decoded["services"]["service1"]
	assert.Equal(t, "running", service["state"])
	assert.Equal(t, true, service["tls"])
	assert.Equal(t, []any{"172.18.0.4:3000"}, service["targets"])
	assert.Equal(t, []any{"172.18.0.5:3000"}, service["reader_targets"])
	assert.Equal(t, []any{"172.18.0.6:3000"}, service["rollout_targets"])
}
