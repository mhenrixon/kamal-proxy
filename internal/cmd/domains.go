package cmd

import (
	"fmt"
	"maps"
	"net/rpc"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/basecamp/kamal-proxy/internal/server"
)

type domainsCommand struct {
	cmd *cobra.Command
}

func newDomainsCommand() *domainsCommand {
	domainsCommand := &domainsCommand{}
	domainsCommand.cmd = &cobra.Command{
		Use:   "domains",
		Short: "Inspect and refresh dynamic TLS domains",
	}

	domainsCommand.cmd.AddCommand(newDomainsListCommand().cmd)
	domainsCommand.cmd.AddCommand(newDomainsStatsCommand().cmd)
	domainsCommand.cmd.AddCommand(newDomainsRefreshCommand().cmd)

	return domainsCommand
}

func fetchDomainsStatus(fn func(response server.DomainsStatusResponse)) error {
	return withRPCClient(globalConfig.SocketPath(), func(client *rpc.Client) error {
		var response server.DomainsStatusResponse

		err := client.Call("kamal-proxy.DomainsStatus", true, &response)
		if err != nil {
			return err
		}

		fn(response)
		return nil
	})
}

type domainsListCommand struct {
	cmd *cobra.Command
}

func newDomainsListCommand() *domainsListCommand {
	domainsListCommand := &domainsListCommand{}
	domainsListCommand.cmd = &cobra.Command{
		Use:     "list",
		Short:   "List dynamic domains by service",
		RunE:    domainsListCommand.run,
		Args:    cobra.NoArgs,
		Aliases: []string{"ls"},
	}

	return domainsListCommand
}

func (c *domainsListCommand) run(cmd *cobra.Command, args []string) error {
	return fetchDomainsStatus(func(response server.DomainsStatusResponse) {
		table := NewTable()
		table.AddRow([]string{"Service", "Domain", "Certified", "Quarantined until"})

		for _, name := range slices.Sorted(maps.Keys(response.Services)) {
			service := response.Services[name]
			domains := slices.SortedFunc(slices.Values(service.Domains), func(a, b server.DomainStatus) int {
				return strings.Compare(a.Domain, b.Domain)
			})

			for _, domain := range domains {
				certified := "no"
				if domain.Certified {
					certified = "yes"
				}

				quarantined := ""
				if entry, ok := response.Quarantine[domain.Domain]; ok {
					quarantined = entry.Until.Format("2006-01-02 15:04:05")
				}

				table.AddRow([]string{name, domain.Domain, certified, quarantined})
			}
		}

		table.Print()
	})
}

type domainsStatsCommand struct {
	cmd *cobra.Command
}

func newDomainsStatsCommand() *domainsStatsCommand {
	domainsStatsCommand := &domainsStatsCommand{}
	domainsStatsCommand.cmd = &cobra.Command{
		Use:   "stats",
		Short: "Show dynamic domain counters",
		RunE:  domainsStatsCommand.run,
		Args:  cobra.NoArgs,
	}

	return domainsStatsCommand
}

func (c *domainsStatsCommand) run(cmd *cobra.Command, args []string) error {
	return fetchDomainsStatus(func(response server.DomainsStatusResponse) {
		domains := 0
		certified := 0
		for _, service := range response.Services {
			domains += len(service.Domains)
			for _, domain := range service.Domains {
				if domain.Certified {
					certified++
				}
			}
		}

		fmt.Printf("Services with domain sources: %d\n", len(response.Services))
		fmt.Printf("Dynamic domains:              %d\n", domains)
		fmt.Printf("Certified:                    %d\n", certified)
		fmt.Printf("Queued for issuance:          %d\n", response.QueueLength)
		fmt.Printf("Quarantined:                  %d\n", len(response.Quarantine))
		fmt.Printf("Managed certificates:         %d\n", response.Certificates)
	})
}

type domainsRefreshCommand struct {
	cmd *cobra.Command
}

func newDomainsRefreshCommand() *domainsRefreshCommand {
	domainsRefreshCommand := &domainsRefreshCommand{}
	domainsRefreshCommand.cmd = &cobra.Command{
		Use:   "refresh",
		Short: "Re-poll every domain source immediately",
		RunE:  domainsRefreshCommand.run,
		Args:  cobra.NoArgs,
	}

	return domainsRefreshCommand
}

func (c *domainsRefreshCommand) run(cmd *cobra.Command, args []string) error {
	return withRPCClient(globalConfig.SocketPath(), func(client *rpc.Client) error {
		var refreshed int

		err := client.Call("kamal-proxy.DomainsRefresh", true, &refreshed)
		if err != nil {
			return err
		}

		if refreshed == 1 {
			fmt.Println("Refresh requested for 1 domain source")
		} else {
			fmt.Printf("Refresh requested for %d domain sources\n", refreshed)
		}
		return nil
	})
}
