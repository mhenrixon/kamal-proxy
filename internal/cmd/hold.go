package cmd

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

// hold blocks until SIGTERM/SIGINT. It exists to own a network namespace
// whose published ports proxy generations share via --network container:.
// The holder must be the one container that is never replaced during normal
// operation — replacing it destroys the namespace and every generation's
// port bindings with it.
type holdCommand struct {
	cmd *cobra.Command
}

func newHoldCommand() *holdCommand {
	holdCommand := &holdCommand{}
	holdCommand.cmd = &cobra.Command{
		Use:    "hold",
		Short:  "Hold a network namespace for proxy generations (orchestration detail)",
		RunE:   holdCommand.run,
		Args:   cobra.NoArgs,
		Hidden: true,
	}

	return holdCommand
}

func (c *holdCommand) run(cmd *cobra.Command, args []string) error {
	slog.Info("Holding network namespace for proxy generations")

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	<-ch

	return nil
}
