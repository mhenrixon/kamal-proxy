package cmd

import (
	"fmt"
	"net/rpc"
	"strings"

	"github.com/spf13/cobra"

	"github.com/basecamp/kamal-proxy/internal/server"
)

type cachePurgeCommand struct {
	cmd  *cobra.Command
	args server.CachePurgeArgs
}

func newCachePurgeCommand() *cachePurgeCommand {
	cachePurgeCommand := &cachePurgeCommand{}
	cachePurgeCommand.cmd = &cobra.Command{
		Use:       "purge <service>",
		Short:     "Drop a service's cached responses",
		PreRunE:   cachePurgeCommand.preRun,
		RunE:      cachePurgeCommand.run,
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"service"},
	}

	cachePurgeCommand.cmd.Flags().StringVar(&cachePurgeCommand.args.PathPrefix, "path-prefix", "", "Purge only the entries below this path, e.g. /assets (default empty, purge all of them)")

	return cachePurgeCommand
}

func (c *cachePurgeCommand) preRun(cmd *cobra.Command, args []string) error {
	if c.args.PathPrefix != "" && !strings.HasPrefix(c.args.PathPrefix, "/") {
		return fmt.Errorf("path-prefix must start with '/', got %q", c.args.PathPrefix)
	}

	return nil
}

func (c *cachePurgeCommand) run(cmd *cobra.Command, args []string) error {
	c.args.Service = args[0]

	return withRPCClient(globalConfig.SocketPath(), func(client *rpc.Client) error {
		var purged int
		if err := client.Call("kamal-proxy.CachePurge", c.args, &purged); err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Purged %d cached %s\n", purged, pluralize(purged, "response"))
		return nil
	})
}

func pluralize(count int, noun string) string {
	if count == 1 {
		return noun
	}

	return noun + "s"
}
