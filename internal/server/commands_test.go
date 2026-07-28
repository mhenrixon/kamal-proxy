package server

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCommandHandler_DeployRejectsInvalidServiceOptions(t *testing.T) {
	handler := NewCommandHandler(testRouter(t))

	var result bool
	err := handler.Deploy(DeployArgs{
		ServiceOptions: ServiceOptions{TLSEnabled: true},
	}, &result)

	require.ErrorContains(t, err, "host must be set when using TLS")
	require.ErrorIs(t, err, ErrServiceOptionsInvalid)
}

func TestCommandHandler_DeployRejectsInvalidTargetOptions(t *testing.T) {
	handler := NewCommandHandler(testRouter(t))

	var result bool
	err := handler.Deploy(DeployArgs{
		TargetURLs:    []string{"localhost:3000"},
		TargetOptions: TargetOptions{MaxConnsPerHost: -1},
	}, &result)

	require.ErrorContains(t, err, "target-max-conns cannot be negative")
	require.ErrorIs(t, err, ErrTargetOptionsInvalid)
}
