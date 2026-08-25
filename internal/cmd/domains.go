package cmd

import (
	"errors"
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
		Short: "Inspect TLS domains and their certificate issuance",
	}

	domainsCommand.cmd.AddCommand(newDomainsListCommand().cmd)
	domainsCommand.cmd.AddCommand(newDomainsStatsCommand().cmd)
	domainsCommand.cmd.AddCommand(newDomainsRefreshCommand().cmd)
	domainsCommand.cmd.AddCommand(newDomainsRetryCommand().cmd)

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
		Short:   "List dynamic domains and registered hosts by service",
		RunE:    domainsListCommand.run,
		Args:    cobra.NoArgs,
		Aliases: []string{"ls"},
	}

	return domainsListCommand
}

func (c *domainsListCommand) run(cmd *cobra.Command, args []string) error {
	return fetchDomainsStatus(func(response server.DomainsStatusResponse) {
		table := NewTable()
		table.AddRow([]string{"Service", "Domain", "Certified", "Quarantined until", "Removal held"})

		for _, name := range slices.Sorted(maps.Keys(response.Services)) {
			service := response.Services[name]
			domains := slices.SortedFunc(slices.Values(service.Domains), func(a, b server.DomainStatus) int {
				return strings.Compare(a.Domain, b.Domain)
			})

			heldRemovals := make(map[string]struct{}, len(service.HeldRemovals))
			for _, domain := range service.HeldRemovals {
				heldRemovals[domain] = struct{}{}
			}

			for _, domain := range domains {
				certified := "no"
				if domain.Certified {
					certified = "yes"
				}

				quarantined := holdDescription(response.Quarantine, domain.Domain)

				held := ""
				if _, ok := heldRemovals[domain.Domain]; ok {
					held = "yes"
				}

				table.AddRow([]string{name, domain.Domain, certified, quarantined, held})
			}
		}

		// Deploy-registered hosts have no domain source to group them under,
		// but they are the common case — and the one an operator is staring at
		// during a DNS cutover, wondering why the certificate has not arrived.
		for _, domain := range slices.Sorted(maps.Keys(response.Registered)) {
			entry := response.Registered[domain]

			certified := "no"
			if entry.Certified {
				certified = "yes"
			}

			table.AddRow([]string{entry.Service, domain, certified, holdDescription(response.Quarantine, domain), ""})
		}

		table.Print()
	})
}

// holdDescription renders a domain's issuance hold for the listing: when it
// lifts, and why it is held, since only some kinds lift on their own.
func holdDescription(quarantine map[string]server.QuarantineStatus, domain string) string {
	entry, ok := quarantine[domain]
	if !ok {
		return ""
	}

	until := entry.Until.Format("2006-01-02 15:04:05")
	if entry.Kind == "" {
		return until
	}
	return until + " (" + entry.Kind + ")"
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
		held := 0
		for _, service := range response.Services {
			domains += len(service.Domains)
			held += len(service.HeldRemovals)
			for _, domain := range service.Domains {
				if domain.Certified {
					certified++
				}
			}
		}

		registeredCertified := 0
		for _, entry := range response.Registered {
			if entry.Certified {
				registeredCertified++
			}
		}

		fmt.Printf("Services with domain sources: %d\n", len(response.Services))
		fmt.Printf("Dynamic domains:              %d\n", domains)
		fmt.Printf("Dynamic certified:            %d\n", certified)
		fmt.Printf("Registered hosts:             %d\n", len(response.Registered))
		fmt.Printf("Registered certified:         %d\n", registeredCertified)
		fmt.Printf("Queued for issuance:          %d\n", response.QueueLength)
		fmt.Printf("Quarantined:                  %d\n", len(response.Quarantine))
		fmt.Printf("Held removals:                %d\n", held)
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

type domainsRetryCommand struct {
	cmd *cobra.Command
	all bool
}

func newDomainsRetryCommand() *domainsRetryCommand {
	domainsRetryCommand := &domainsRetryCommand{}
	domainsRetryCommand.cmd = &cobra.Command{
		Use:   "retry [domain]",
		Short: "Clear an issuance hold and try again now",
		Long: "Clear the issuance hold on a domain and request its certificate again.\n\n" +
			"Holds normally lift on their own once the domain routes back to this proxy,\n" +
			"so reach for this when you know the cause is fixed and do not want to wait —\n" +
			"including for a rate-limit hold, whose window the automatic release respects.",
		RunE: domainsRetryCommand.run,
		Args: cobra.MaximumNArgs(1),
	}

	domainsRetryCommand.cmd.Flags().BoolVar(&domainsRetryCommand.all, "all", false, "Clear every issuance hold")

	return domainsRetryCommand
}

func (c *domainsRetryCommand) run(cmd *cobra.Command, args []string) error {
	if len(args) == 0 && !c.all {
		return errors.New("specify a domain, or --all to clear every hold")
	}
	if len(args) > 0 && c.all {
		return errors.New("specify a domain or --all, not both")
	}

	domain := ""
	if len(args) > 0 {
		domain = args[0]
	}

	return withRPCClient(globalConfig.SocketPath(), func(client *rpc.Client) error {
		var cleared int

		err := client.Call("kamal-proxy.DomainsRetry", server.DomainsRetryArgs{Domain: domain}, &cleared)
		if err != nil {
			return err
		}

		switch {
		case cleared == 0 && domain != "":
			fmt.Printf("No issuance hold on %s\n", domain)
		case cleared == 0:
			fmt.Println("No issuance holds to clear")
		case cleared == 1:
			fmt.Println("Cleared 1 issuance hold")
		default:
			fmt.Printf("Cleared %d issuance holds\n", cleared)
		}
		return nil
	})
}
