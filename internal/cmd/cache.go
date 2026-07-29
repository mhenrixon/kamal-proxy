package cmd

import "github.com/spf13/cobra"

type cacheCommand struct {
	cmd *cobra.Command
}

func newCacheCommand() *cacheCommand {
	cacheCommand := &cacheCommand{}
	cacheCommand.cmd = &cobra.Command{
		Use:   "cache",
		Short: "Manage the response cache",
	}

	cacheCommand.cmd.AddCommand(newCachePurgeCommand().cmd)

	return cacheCommand
}
