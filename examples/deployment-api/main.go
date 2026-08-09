package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/olegkapshai/auth-master/examples/internal/authz"
)

func main() {
	app := deploymentApp{checker: authz.HTTPChecker{BaseURL: env("AUTH_HTTP_URL", "http://localhost:8080")}}
	server := &http.Server{Addr: env("HTTP_ADDR", ":8092"), Handler: app.routes(), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("deployment API example listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
