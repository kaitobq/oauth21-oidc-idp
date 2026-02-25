package main

import (
	"log"
	"net/http"

	"github.com/kaitobq/oauth21-oidc-idp/backend/internal/di"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func main() {
	container := di.NewContainer()

	mux := http.NewServeMux()
	container.RegisterRoutes(mux)

	addr := container.Config.Addr()
	log.Printf("server listening on %s", addr)

	err := http.ListenAndServe(addr, h2c.NewHandler(mux, &http2.Server{}))
	if err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
