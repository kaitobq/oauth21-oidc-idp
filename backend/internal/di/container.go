package di

import (
	"net/http"

	app "github.com/kaitobq/oauth21-oidc-idp/backend/internal/application/organization"
	"github.com/kaitobq/oauth21-oidc-idp/backend/internal/config"
	"github.com/kaitobq/oauth21-oidc-idp/backend/internal/gen/organization/v1/organizationv1connect"
	handler "github.com/kaitobq/oauth21-oidc-idp/backend/internal/handler/organization"
	infra "github.com/kaitobq/oauth21-oidc-idp/backend/internal/infra/organization"
)

// Container wires all dependencies.
type Container struct {
	Config              *config.Config
	organizationHandler *handler.Handler
}

// NewContainer builds the dependency graph.
func NewContainer() *Container {
	cfg := config.Load()

	// TODO: Initialize actual DB connection
	// db, err := mysql.NewDB(cfg.DSN())
	repo := infra.NewMySQLRepository(nil) // placeholder until DB is wired

	facade := app.NewFacade(repo)
	orgHandler := handler.NewHandler(facade)

	return &Container{
		Config:              cfg,
		organizationHandler: orgHandler,
	}
}

// RegisterRoutes registers all Connect RPC handlers on the given mux.
func (c *Container) RegisterRoutes(mux *http.ServeMux) {
	path, h := organizationv1connect.NewOrganizationServiceHandler(c.organizationHandler)
	mux.Handle(path, h)
}
