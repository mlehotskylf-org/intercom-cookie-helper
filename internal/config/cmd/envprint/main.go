package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/mlehotskylf-org/intercom-cookie-helper/internal/config"
)

// ConfigJSON is the JSON representation of config with secrets redacted
type ConfigJSON struct {
	Env                string   `json:"env"`
	AppHostname        string   `json:"app_hostname"`
	Port               string   `json:"port"`
	CookieDomain       string   `json:"cookie_domain"`
	AllowedReturnHosts []string `json:"allowed_return_hosts"`
	AllowedQueryParams []string `json:"allowed_query_params"`
	IntercomAppID      string   `json:"intercom_app_id"`
	IntercomJWTSecret  string   `json:"intercom_jwt_secret"`
	Auth0Domain        string   `json:"auth0_domain"`
	Auth0ClientID      string   `json:"auth0_client_id"`
	Auth0ClientSecret  string   `json:"auth0_client_secret"`
	Auth0RedirectPath  string   `json:"auth0_redirect_path"`
	CookieSigningKey   string   `json:"cookie_signing_key"`
	RedirectTTL        string   `json:"redirect_ttl"`
	SessionTTL         string   `json:"session_ttl"`
	LogLevel           string   `json:"log_level"`
	EnableHSTS         bool     `json:"enable_hsts"`
}

func main() {
	cfg, err := config.FromEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Convert to JSON struct with redacted secrets
	jsonCfg := ConfigJSON{
		Env:                cfg.Env,
		AppHostname:        cfg.AppHostname,
		Port:               cfg.Port,
		CookieDomain:       cfg.CookieDomain,
		AllowedReturnHosts: cfg.AllowedReturnHosts,
		AllowedQueryParams: cfg.AllowedQueryParams,
		IntercomAppID:      cfg.IntercomAppID,
		IntercomJWTSecret:  redactSecret(cfg.IntercomJWTSecret),
		Auth0Domain:        cfg.Auth0Domain,
		Auth0ClientID:      cfg.Auth0ClientID,
		Auth0ClientSecret:  redactSecret(cfg.Auth0ClientSecret),
		Auth0RedirectPath:  cfg.Auth0RedirectPath,
		CookieSigningKey:   redactKey(cfg.CookieSigningKey),
		RedirectTTL:        cfg.RedirectTTL.String(),
		SessionTTL:         cfg.SessionTTL.String(),
		LogLevel:           cfg.LogLevel,
		EnableHSTS:         cfg.EnableHSTS,
	}

	// Print as pretty JSON
	output, err := json.MarshalIndent(jsonCfg, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling config: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(output))
}

func redactSecret(secret string) string {
	if secret == "" {
		return "(not set)"
	}
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	// Show first 3 and last 3 characters
	return secret[:3] + strings.Repeat("*", len(secret)-6) + secret[len(secret)-3:]
}

func redactKey(key []byte) string {
	if len(key) == 0 {
		return "(not set)"
	}
	return fmt.Sprintf("(set, %d bytes)", len(key))
}