package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/rpc"
	"strings"

	"github.com/spf13/cobra"

	"github.com/basecamp/kamal-proxy/internal/server"
)

type cacheStatsCommand struct {
	cmd      *cobra.Command
	args     server.CacheStatsArgs
	asJSON   bool
	response server.CacheStats
}

func newCacheStatsCommand() *cacheStatsCommand {
	cacheStatsCommand := &cacheStatsCommand{}
	cacheStatsCommand.cmd = &cobra.Command{
		Use:   "stats",
		Short: "Report what the response cache is holding",
		RunE:  cacheStatsCommand.run,
		Args:  cobra.NoArgs,
	}

	cacheStatsCommand.cmd.Flags().BoolVar(&cacheStatsCommand.args.Count, "count", false, "Measure entries and bytes, and break them down by service. On a shared --cache-store this walks the keyspace, which is why it is not the default -- it is also the only truthful answer a shared store has to 'how big is my cache'")
	cacheStatsCommand.cmd.Flags().BoolVar(&cacheStatsCommand.asJSON, "json", false, "Print the raw report as JSON")

	return cacheStatsCommand
}

func (c *cacheStatsCommand) run(cmd *cobra.Command, args []string) error {
	return withRPCClient(globalConfig.SocketPath(), func(client *rpc.Client) error {
		if err := client.Call("kamal-proxy.CacheStats", c.args, &c.response); err != nil {
			return err
		}

		if c.asJSON {
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			return encoder.Encode(c.response)
		}

		printCacheStats(cmd.OutOrStdout(), c.response)
		return nil
	})
}

// printCacheStats lays the report out so the sizing question answers itself:
// evictions of still-fresh entries next to how full the cache is.
func printCacheStats(out io.Writer, stats server.CacheStats) {
	scope := "per node"
	if stats.Shared {
		scope = "shared"
	}
	fmt.Fprintf(out, "Store        %s (%s)\n", stats.Store, scope)

	if stats.Local.Counted {
		fmt.Fprintf(out, "Entries      %s\n", formatCount(stats.Local.Entries))

		if stats.Local.MaxBytes > 0 {
			fmt.Fprintf(out, "Size         %s of %s (%d%%)\n",
				formatBytes(stats.Local.Bytes), formatBytes(stats.Local.MaxBytes),
				stats.Local.Bytes*100/stats.Local.MaxBytes)
		} else {
			fmt.Fprintf(out, "Size         %s stored\n", formatBytes(stats.Local.Bytes))
		}
	} else {
		fmt.Fprintln(out, "Entries      not counted -- pass --count to measure this proxy's keys")
	}

	// The line that answers "is the budget big enough". Fresh evictions mean
	// entries were fetched and pushed out before they were used up.
	fmt.Fprintf(out, "Evicted      %s fresh, %s stale\n",
		formatCount(stats.Local.EvictedFresh), formatCount(stats.Local.EvictedStale))

	if stats.Local.Oversized > 0 {
		fmt.Fprintf(out, "Oversized    %s refused for exceeding --cache-max-body\n", formatCount(stats.Local.Oversized))
	}

	printCacheServiceStats(out, stats.Local.Services)
	printCacheServerStats(out, stats.Server)
}

func printCacheServiceStats(out io.Writer, services []server.CacheServiceStats) {
	if len(services) == 0 {
		return
	}

	fmt.Fprintf(out, "\n%-20s %10s %12s\n", "Service", "Entries", "Size")
	for _, service := range services {
		fmt.Fprintf(out, "%-20s %10s %12s\n", service.Service, formatCount(service.Entries), formatBytes(service.Bytes))
	}
}

func printCacheServerStats(out io.Writer, stats *server.CacheServerStats) {
	if stats == nil {
		return
	}

	fmt.Fprintf(out, "\n%s\n", "Cache server -- shared with anything else using it")
	fmt.Fprintf(out, "Keys         %s (every key in the database, not only this proxy's)\n", formatCount(stats.Keys))

	used := formatBytes(stats.UsedBytes)
	if stats.Unknown("used_bytes") {
		used = "unknown"
	}

	limit := formatBytes(stats.MaxBytes)
	switch {
	case stats.Unknown("max_bytes"):
		limit = "unknown"
	case stats.MaxBytes == 0:
		limit = "no limit"
	}

	policy := stats.Policy
	if stats.Unknown("eviction_policy") {
		policy = "unknown"
	}

	fmt.Fprintf(out, "Used memory  %s of %s, policy %s\n", used, limit, policy)

	if len(stats.Unavailable) > 0 {
		fmt.Fprintf(out, "             (%s withheld by the server)\n", strings.Join(stats.Unavailable, ", "))
	}
}

// formatBytes renders a size the way an operator setting --cache-memory-size
// thinks about it.
func formatBytes(bytes int64) string {
	const unit = 1024

	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	value := float64(bytes)
	units := []string{"KB", "MB", "GB", "TB"}

	for _, suffix := range units {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
	}

	return fmt.Sprintf("%.1f PB", value/unit)
}

// formatCount groups thousands, so a six-figure entry count is readable at a
// glance.
func formatCount(count int64) string {
	digits := fmt.Sprintf("%d", count)
	if len(digits) <= 3 {
		return digits
	}

	var grouped strings.Builder
	for i, digit := range digits {
		if i > 0 && (len(digits)-i)%3 == 0 {
			grouped.WriteByte(',')
		}
		grouped.WriteRune(digit)
	}

	return grouped.String()
}
