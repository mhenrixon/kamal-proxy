package cmd

import (
	"fmt"
	"net/rpc"
	"os"
	"strconv"
	"time"
)

const (
	ENV_PREFIX = "KAMAL_PROXY_"
)

// ensureDataDir creates the --data-dir when one was supplied, so state and
// certificate files can be written into it on first use. Shared by every
// command that writes into the data directory (`run`, `import certs`).
func ensureDataDir() error {
	if globalConfig.AlternateConfigDir == "" {
		return nil
	}

	if err := os.MkdirAll(globalConfig.AlternateConfigDir, 0700); err != nil {
		return fmt.Errorf("failed to create data directory %q: %w", globalConfig.AlternateConfigDir, err)
	}
	return nil
}

func withRPCClient(socketPath string, fn func(client *rpc.Client) error) error {
	client, err := rpc.Dial("unix", socketPath)
	if err != nil {
		return err
	}
	defer client.Close()
	return fn(client)
}

func findEnv(key string) (string, bool) {
	value, ok := os.LookupEnv(ENV_PREFIX + key)
	if ok {
		return value, true
	}

	value, ok = os.LookupEnv(key)
	if ok {
		return value, true
	}

	return "", false
}

func getEnvInt(key string, defaultValue int) int {
	value, ok := findEnv(key)
	if !ok {
		return defaultValue
	}

	intValue, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}

	return intValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	value, ok := findEnv(key)
	if !ok {
		return defaultValue
	}

	durationValue, err := time.ParseDuration(value)
	if err != nil {
		return defaultValue
	}

	return durationValue
}

func getEnvBool(key string, defaultValue bool) bool {
	value, ok := findEnv(key)
	if !ok {
		return defaultValue
	}

	boolValue, err := strconv.ParseBool(value)
	if err != nil {
		return defaultValue
	}

	return boolValue
}

func getEnvString(key string, defaultValue string) string {
	value, ok := findEnv(key)
	if !ok {
		return defaultValue
	}
	return value
}
