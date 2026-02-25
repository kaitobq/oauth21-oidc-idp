package di

import (
	"fmt"
	"net/http"

	app "github.com/kaitobq/oauth21-oidc-idp/backend/internal/application/organization"
	"github.com/kaitobq/oauth21-oidc-idp/backend/internal/config"
	"github.com/kaitobq/oauth21-oidc-idp/backend/internal/gen/organization/v1/organizationv1connect"
	handler "github.com/kaitobq/oauth21-oidc-idp/backend/internal/handler/organization"
	"github.com/kaitobq/oauth21-oidc-idp/backend/internal/infra/authz"
	"github.com/kaitobq/oauth21-oidc-idp/backend/internal/infra/mysql"
	infra "github.com/kaitobq/oauth21-oidc-idp/backend/internal/infra/organization"
)

// Container wires all dependencies.
type Container struct {
	Config              *config.Config
	organizationHandler *handler.Handler
}

// NewContainer builds the dependency graph.
func NewContainer() (*Container, error) {
	cfg := config.Load()

	db, err := mysql.NewDB(cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("initialize mysql: %w", err)
	}
	repo := infra.NewMySQLRepository(db)
	commandService := app.NewCommandService(repo)
	queryService := app.NewQueryService(repo)
	authzGateway := authz.NewNoopGateway()

	facade := app.NewFacade(commandService, queryService, authzGateway)
	orgHandler := handler.NewHandler(facade)

	return &Container{
		Config:              cfg,
		organizationHandler: orgHandler,
	}, nil
}

// RegisterRoutes registers all Connect RPC handlers on the given mux.
func (c *Container) RegisterRoutes(mux *http.ServeMux) {
	path, h := organizationv1connect.NewOrganizationServiceHandler(c.organizationHandler)
	mux.Handle(path, h)
}
