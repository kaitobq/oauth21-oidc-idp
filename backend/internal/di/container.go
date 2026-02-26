package di

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	app "github.com/kaitobq/oauth21-oidc-idp/backend/internal/application/organization"
	"github.com/kaitobq/oauth21-oidc-idp/backend/internal/config"
	"github.com/kaitobq/oauth21-oidc-idp/backend/internal/gen/organization/v1/organizationv1connect"
	oidcHandler "github.com/kaitobq/oauth21-oidc-idp/backend/internal/handler/oidc"
	handler "github.com/kaitobq/oauth21-oidc-idp/backend/internal/handler/organization"
	"github.com/kaitobq/oauth21-oidc-idp/backend/internal/infra/authz"
	"github.com/kaitobq/oauth21-oidc-idp/backend/internal/infra/mysql"
	infraOIDC "github.com/kaitobq/oauth21-oidc-idp/backend/internal/infra/oidc"
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

	provider, err := coreOIDC.NewProvider(cfg.Issuer, cfg.DevClientID, cfg.DevClientRedirectURI)
	if err != nil {
		return nil, fmt.Errorf("initialize oidc provider: %w", err)
	}
	if strings.TrimSpace(cfg.ClientRegistryPath) != "" {
		clientStore, err := infraOIDC.NewFileClientStore(cfg.ClientRegistryPath)
		if err != nil {
			return nil, fmt.Errorf("initialize oidc client store: %w", err)
		}
		if err := provider.ConfigureClientStore(context.Background(), clientStore); err != nil {
			return nil, fmt.Errorf("configure oidc client store: %w", err)
		}
	}
	if cfg.ConfidentialClientID != coreOIDC.DefaultConfidentialClientID ||
		cfg.ConfidentialSecret != coreOIDC.DefaultConfidentialClientSecret ||
		cfg.ConfidentialRedirect != coreOIDC.DefaultConfidentialRedirect {
		if err := provider.RegisterConfidentialClient(
			cfg.ConfidentialClientID,
			cfg.ConfidentialSecret,
			cfg.ConfidentialRedirect,
		); err != nil {
			return nil, fmt.Errorf("register confidential oidc client: %w", err)
		}
	}
	if cfg.EnablePrivateJWT {
		publicKeyPEM := strings.TrimSpace(cfg.PrivateJWTPublicKeyPEM)
		if publicKeyPEM == "" {
			rawPublicKey, err := os.ReadFile(cfg.PrivateJWTPublicKeyPath)
			if err != nil {
				return nil, fmt.Errorf("read private_key_jwt public key file: %w", err)
			}
			publicKeyPEM = strings.TrimSpace(string(rawPublicKey))
		}
		if err := provider.RegisterPrivateJWTClient(
			cfg.PrivateJWTClientID,
			cfg.PrivateJWTRedirectURI,
			publicKeyPEM,
		); err != nil {
			return nil, fmt.Errorf("register private_key_jwt oidc client: %w", err)
		}
	}
	oidc := oidcHandler.NewHandler(provider)
	if cfg.EnableSigningKeyRotationAPI && cfg.EnablePrivateJWTKeyRotation {
		oidc = oidcHandler.NewHandlerWithAdminAPIsAuth(
			provider,
			cfg.SigningKeyRotationToken,
			cfg.PrivateJWTKeyRotationToken,
			cfg.AdminAuthMode,
			cfg.AdminJWTSecret,
			cfg.AdminJWTIssuer,
			cfg.AdminJWTAudience,
		)
	} else if cfg.EnableSigningKeyRotationAPI {
		oidc = oidcHandler.NewHandlerWithSigningKeyRotationAuth(
			provider,
			cfg.SigningKeyRotationToken,
			cfg.AdminAuthMode,
			cfg.AdminJWTSecret,
			cfg.AdminJWTIssuer,
			cfg.AdminJWTAudience,
		)
	} else if cfg.EnablePrivateJWTKeyRotation {
		oidc = oidcHandler.NewHandlerWithPrivateJWTClientKeyRotationAuth(
			provider,
			cfg.PrivateJWTKeyRotationToken,
			cfg.AdminAuthMode,
			cfg.AdminJWTSecret,
			cfg.AdminJWTIssuer,
			cfg.AdminJWTAudience,
		)
	}

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
	if err := mysql.EnsureOrganizationSchema(context.Background(), db); err != nil {
		return nil, fmt.Errorf("ensure organization schema: %w", err)
	}
	repo := infra.NewMySQLRepository(db)
	commandService := app.NewCommandService(repo)
	queryService := app.NewQueryService(repo)
	authzGateway := authz.NewScopeGateway()

	facade := app.NewFacade(commandService, queryService, authzGateway)
	container.organizationHandler = handler.NewHandlerWithAuth(facade, handler.AuthConfig{
		Mode:        cfg.OrganizationAuthMode,
		StaticToken: cfg.OrganizationAuthStaticToken,
		JWTSecret:   cfg.OrganizationJWTSecret,
		JWTIssuer:   cfg.OrganizationJWTIssuer,
		JWTAudience: cfg.OrganizationJWTAudience,
	})
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
