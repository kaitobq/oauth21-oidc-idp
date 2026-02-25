package di

import (
	"fmt"
	"log"
	"net/http"

	app "github.com/kaitobq/oauth21-oidc-idp/backend/internal/application/organization"
	"github.com/kaitobq/oauth21-oidc-idp/backend/internal/config"
	"github.com/kaitobq/oauth21-oidc-idp/backend/internal/gen/organization/v1/organizationv1connect"
	oidcHandler "github.com/kaitobq/oauth21-oidc-idp/backend/internal/handler/oidc"
	handler "github.com/kaitobq/oauth21-oidc-idp/backend/internal/handler/organization"
	"github.com/kaitobq/oauth21-oidc-idp/backend/internal/infra/authz"
	"github.com/kaitobq/oauth21-oidc-idp/backend/internal/infra/mysql"
	infra "github.com/kaitobq/oauth21-oidc-idp/backend/internal/infra/organization"
	coreOIDC "github.com/kaitobq/oauth21-oidc-idp/backend/internal/oidc"
)

// Container wires all dependencies.
type Container struct {
	Config              *config.Config
	oidcHandler         *oidcHandler.Handler
	organizationHandler *handler.Handler
}

// NewContainer builds the dependency graph.
func NewContainer() (*Container, error) {
	cfg := config.Load()

	provider, err := coreOIDC.NewProvider(cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("initialize oidc provider: %w", err)
	}
	oidc := oidcHandler.NewHandler(provider)

	container := &Container{
		Config:      cfg,
		oidcHandler: oidc,
	}

	if !cfg.EnableOrganizationAPI {
		return container, nil
	}

	db, err := mysql.NewDB(cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("initialize mysql for organization API: %w", err)
	}
	repo := infra.NewMySQLRepository(db)
	commandService := app.NewCommandService(repo)
	queryService := app.NewQueryService(repo)
	authzGateway := authz.NewNoopGateway()

	facade := app.NewFacade(commandService, queryService, authzGateway)
	container.organizationHandler = handler.NewHandler(facade)
	log.Printf("organization API is enabled")
	return container, nil
}

// RegisterRoutes registers all Connect RPC handlers on the given mux.
func (c *Container) RegisterRoutes(mux *http.ServeMux) {
	c.oidcHandler.RegisterRoutes(mux)
	if c.organizationHandler == nil {
		return
	}
	path, h := organizationv1connect.NewOrganizationServiceHandler(c.organizationHandler)
	mux.Handle(path, h)
}
