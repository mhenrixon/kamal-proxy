package cmd

import (
	"encoding/json"
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

func fetchDomainsStatus(fn func(response server.DomainsStatusResponse) error) error {
	return withRPCClient(globalConfig.SocketPath(), func(client *rpc.Client) error {
		var response server.DomainsStatusResponse

		err := client.Call("kamal-proxy.DomainsStatus", true, &response)
		if err != nil {
			return err
		}

		return fn(response)
	})
}

func printJSON(value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(data))
	return nil
}

type domainsListCommand struct {
	cmd  *cobra.Command
	json bool
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

	domainsListCommand.cmd.Flags().BoolVar(&domainsListCommand.json, "json", false, "Output the domain list as JSON")

	return domainsListCommand
}

func (c *domainsListCommand) run(cmd *cobra.Command, args []string) error {
	return fetchDomainsStatus(func(response server.DomainsStatusResponse) error {
		if c.json {
			return printJSON(response)
		}

		c.displayTable(response)
		return nil
	})
}

func (c *domainsListCommand) displayTable(response server.DomainsStatusResponse) {
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
	cmd  *cobra.Command
	json bool
}

// DomainsStatsSummary is the machine-readable form of `domains stats`.
type DomainsStatsSummary struct {
	Services            int `json:"services"`
	DynamicDomains      int `json:"dynamic_domains"`
	DynamicCertified    int `json:"dynamic_certified"`
	RegisteredHosts     int `json:"registered_hosts"`
	RegisteredCertified int `json:"registered_certified"`
	Queued              int `json:"queued"`
	Quarantined         int `json:"quarantined"`
	HeldRemovals        int `json:"held_removals"`
	Certificates        int `json:"certificates"`
}

func newDomainsStatsCommand() *domainsStatsCommand {
	domainsStatsCommand := &domainsStatsCommand{}
	domainsStatsCommand.cmd = &cobra.Command{
		Use:   "stats",
		Short: "Show dynamic domain counters",
		RunE:  domainsStatsCommand.run,
		Args:  cobra.NoArgs,
	}

	domainsStatsCommand.cmd.Flags().BoolVar(&domainsStatsCommand.json, "json", false, "Output the counters as JSON")

	return domainsStatsCommand
}

func (c *domainsStatsCommand) run(cmd *cobra.Command, args []string) error {
	return fetchDomainsStatus(func(response server.DomainsStatusResponse) error {
		summary := summarizeDomains(response)

		if c.json {
			return printJSON(summary)
		}

		fmt.Printf("Services with domain sources: %d\n", summary.Services)
		fmt.Printf("Dynamic domains:              %d\n", summary.DynamicDomains)
		fmt.Printf("Dynamic certified:            %d\n", summary.DynamicCertified)
		fmt.Printf("Registered hosts:             %d\n", summary.RegisteredHosts)
		fmt.Printf("Registered certified:         %d\n", summary.RegisteredCertified)
		fmt.Printf("Queued for issuance:          %d\n", summary.Queued)
		fmt.Printf("Quarantined:                  %d\n", summary.Quarantined)
		fmt.Printf("Held removals:                %d\n", summary.HeldRemovals)
		fmt.Printf("Managed certificates:         %d\n", summary.Certificates)
		return nil
	})
}

func summarizeDomains(response server.DomainsStatusResponse) DomainsStatsSummary {
	summary := DomainsStatsSummary{
		Services:        len(response.Services),
		RegisteredHosts: len(response.Registered),
		Queued:          response.QueueLength,
		Quarantined:     len(response.Quarantine),
		Certificates:    response.Certificates,
	}

	for _, service := range response.Services {
		summary.DynamicDomains += len(service.Domains)
		summary.HeldRemovals += len(service.HeldRemovals)
		for _, domain := range service.Domains {
			if domain.Certified {
				summary.DynamicCertified++
			}
		}
	}

	for _, entry := range response.Registered {
		if entry.Certified {
			summary.RegisteredCertified++
		}
	}

	return summary
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
