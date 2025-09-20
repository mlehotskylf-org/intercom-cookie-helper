package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
	httpx "github.com/mlehotskylf-org/intercom-cookie-helper/internal/http"
)

func logKV(kv ...any) {
	timestamp := time.Now().Format(time.RFC3339)
	fmt.Printf("%s", timestamp)
	for i := 0; i < len(kv); i += 2 {
		if i+1 < len(kv) {
			fmt.Printf(" %v:%v", kv[i], kv[i+1])
		}
	}
	fmt.Println()
}

func main() {
	checkConfig := flag.Bool("check-config", false, "Check configuration and exit")
	flag.Parse()

	cfg, err := config.FromEnv()
	if err != nil {
		logKV("event", "config_error", "error", err.Error())
		os.Exit(2)
	}

	// Validate configuration in dev mode
	// In prod, validation can be relaxed since secrets come from secret manager
	if cfg.Env == "dev" {
		if err := cfg.Validate(); err != nil {
			logKV("event", "validation_error", "error", err.Error())
			os.Exit(2)
		}
	}

	// If check-config flag is set, just validate and exit
	if *checkConfig {
		fmt.Println("CONFIG OK")
		os.Exit(0)
	}

	router := httpx.NewRouter()

	addr := ":" + cfg.Port
	logKV("event", "start",
		"env", cfg.Env,
		"port", cfg.Port,
		"hostname", cfg.AppHostname,
		"cookie_domain", cfg.CookieDomain,
		"log_level", cfg.LogLevel)

	if err := http.ListenAndServe(addr, router); err != nil {
		logKV("event", "fatal", "error", err.Error())
		os.Exit(1)
	}
}
