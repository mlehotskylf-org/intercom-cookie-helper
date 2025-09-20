package main

import (
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
	cfg, err := config.FromEnv()
	if err != nil {
		logKV("event", "fatal", "error", err.Error())
		os.Exit(1)
	}

	// Validate configuration in dev mode
	// In prod, validation can be relaxed since secrets come from secret manager
	if cfg.Env == "dev" {
		if err := cfg.Validate(); err != nil {
			logKV("event", "fatal", "error", err.Error())
			os.Exit(1)
		}
	}

	router := httpx.NewRouter()

	addr := ":" + cfg.Port
	logKV("event", "start", "port", cfg.Port, "env", cfg.Env)
	if err := http.ListenAndServe(addr, router); err != nil {
		logKV("event", "fatal", "error", err.Error())
		os.Exit(1)
	}
}
