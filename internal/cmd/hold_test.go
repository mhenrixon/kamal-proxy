package cmd

import (
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHoldCommand_IsHidden(t *testing.T) {
	cmd := newHoldCommand().cmd

	assert.True(t, cmd.Hidden)
	assert.Equal(t, "hold", cmd.Name())
}

func TestHoldCommand_ExitsCleanlyOnSIGTERM(t *testing.T) {
	done := make(chan error, 1)
	go func() {
		done <- newHoldCommand().cmd.RunE(nil, nil)
	}()

	// Give the signal handler time to install, then deliver SIGTERM to
	// ourselves; only the hold command's channel is listening for it here.
	time.Sleep(50 * time.Millisecond)
	p, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	require.NoError(t, p.Signal(syscall.SIGTERM))

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("hold did not exit after SIGTERM")
	}
}
