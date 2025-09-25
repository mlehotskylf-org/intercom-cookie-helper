package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
)

func main() {
	cfg, err := config.FromEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Use the Redacted() method to get safe config
	redacted := cfg.Redacted()

	// Print as pretty JSON
	output, err := json.MarshalIndent(redacted, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling config: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(output))
}
