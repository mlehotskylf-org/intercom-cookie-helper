package main

import (
	"log"
	"net/http"
	"os"

	httpx "github.com/mlehotskylf-org/intercom-cookie-helper/internal/http"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	router := httpx.NewRouter()

	addr := ":" + port
	log.Printf("Starting server on %s", addr)
	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatal(err)
	}
}
