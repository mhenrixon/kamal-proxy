// Command gen rewrites the README's supported-DNS-provider table from the
// provider registry. Run via `go generate ./internal/server/acme/providers`;
// TestREADMEProviderTable_MatchesRegistry fails the build when the committed
// table does not match what this would write.
package main

import (
	"fmt"
	"os"

	"github.com/basecamp/kamal-proxy/internal/server/acme/providers"
)

func main() {
	const readme = "../../../../README.md"

	data, err := os.ReadFile(readme)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gen: %v\n", err)
		os.Exit(1)
	}

	replaced, err := providers.ReplaceProviderTable(string(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "gen: %v\n", err)
		os.Exit(1)
	}

	if replaced == string(data) {
		return
	}

	if err := os.WriteFile(readme, []byte(replaced), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "gen: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("gen: README.md provider table regenerated")
}
