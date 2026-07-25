package cmd

import (
	"net/rpc"
	"time"

	"github.com/spf13/cobra"

	"github.com/basecamp/kamal-proxy/internal/server"
)

type drainCommand struct {
	cmd          *cobra.Command
	drainTimeout time.Duration
}

func newDrainCommand() *drainCommand {
	drainCommand := &drainCommand{}
	drainCommand.cmd = &cobra.Command{
		Use:   "drain",
		Short: "Stop accepting new connections, drain in-flight requests, save state, and exit",
		RunE:  drainCommand.run,
		Args:  cobra.NoArgs,
	}

	drainCommand.cmd.Flags().DurationVar(&drainCommand.drainTimeout, "drain-timeout", 0, "Maximum time to wait for in-flight requests (default: the server's shutdown timeout)")

	return drainCommand
}

func (c *drainCommand) run(cmd *cobra.Command, args []string) error {
	return withRPCClient(globalConfig.SocketPath(), func(client *rpc.Client) error {
		var response bool

		// Blocks until the drain has completed and state is flushed; the
		// server process exits shortly after replying.
		return client.Call("kamal-proxy.Drain", server.DrainArgs{Timeout: c.drainTimeout}, &response)
	})
}
