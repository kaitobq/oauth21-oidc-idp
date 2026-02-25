package authz

import (
	"context"

	app "github.com/kaitobq/oauth21-oidc-idp/backend/internal/application/organization"
)

// NoopGateway allows all actions. Replace with a real policy engine implementation.
type NoopGateway struct{}

var _ app.AuthzGateway = (*NoopGateway)(nil)

func NewNoopGateway() *NoopGateway {
	return &NoopGateway{}
}

func (g *NoopGateway) AuthorizeCreateOrganization(_ context.Context, _ *app.Actor) error {
	return nil
}

func (g *NoopGateway) AuthorizeGetOrganization(_ context.Context, _ *app.Actor) error {
	return nil
}

func (g *NoopGateway) AuthorizeListOrganizations(_ context.Context, _ *app.Actor) error {
	return nil
}
