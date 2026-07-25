package cmd

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/rpc"
	"slices"

	"github.com/spf13/cobra"

	"github.com/basecamp/kamal-proxy/internal/server"
)

type listCommand struct {
	cmd  *cobra.Command
	json bool
}

func newListCommand() *listCommand {
	listCommand := &listCommand{}
	listCommand.cmd = &cobra.Command{
		Use:     "list",
		Short:   "List the services currently running",
		RunE:    listCommand.run,
		Args:    cobra.NoArgs,
		Aliases: []string{"ls"},
	}

	listCommand.cmd.Flags().BoolVar(&listCommand.json, "json", false, "Output the service list as JSON")

	return listCommand
}

func (c *listCommand) run(cmd *cobra.Command, args []string) error {
	return withRPCClient(globalConfig.SocketPath(), func(client *rpc.Client) error {
		var response server.ListResponse

		err := client.Call("kamal-proxy.List", true, &response)
		if err != nil {
			return err
		}

		if c.json {
			return c.displayJSON(response)
		}

		c.displayResponse(response)
		return nil
	})
}

func (c *listCommand) displayJSON(response server.ListResponse) error {
	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(data))
	return nil
}

func (c *listCommand) displayResponse(response server.ListResponse) {
	table := NewTable()
	table.AddRow([]string{"Service", "Host", "Path", "Target", "State", "TLS"})

	sortedKeys := slices.Sorted(maps.Keys(response.Targets))
	for _, name := range sortedKeys {
		service := response.Targets[name]
		tls := "no"
		if service.TLS {
			tls = "yes"
		}

		table.AddRow([]string{name, service.Host, service.Path, service.Target, service.State, tls})
	}

	table.Print()
}
