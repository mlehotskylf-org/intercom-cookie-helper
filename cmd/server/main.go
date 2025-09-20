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

// Log level constants
const (
	LogLevelDebug = 0
	LogLevelInfo  = 1
	LogLevelWarn  = 2
	LogLevelError = 3
)

// Global log threshold
var logThreshold = LogLevelInfo

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

// logLevelToInt maps log level strings to integers
func logLevelToInt(level string) int {
	switch level {
	case "debug":
		return LogLevelDebug
	case "info":
		return LogLevelInfo
	case "warn":
		return LogLevelWarn
	case "error":
		return LogLevelError
	default:
		return LogLevelInfo // default to info
	}
}

// logAt logs at the specified level if it meets the threshold
func logAt(level string, kv ...any) {
	if logLevelToInt(level) >= logThreshold {
		logKV(kv...)
	}
}

func main() {
	checkConfig := flag.Bool("check-config", false, "Check configuration and exit")
	flag.Parse()

	cfg, err := config.FromEnv()
	if err != nil {
		logKV("event", "config_error", "error", err.Error())
		os.Exit(2)
	}

	// Set log threshold based on configuration
	logThreshold = logLevelToInt(cfg.LogLevel)

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
	logAt("info", "event", "start",
		"env", cfg.Env,
		"port", cfg.Port,
		"hostname", cfg.AppHostname,
		"cookie_domain", cfg.CookieDomain,
		"log_level", cfg.LogLevel)

	logAt("debug", "event", "router_initialized", "middleware", "RequestID,RealIP,Logger,Recoverer")

	if err := http.ListenAndServe(addr, router); err != nil {
		logKV("event", "fatal", "error", err.Error())
		os.Exit(1)
	}
}
