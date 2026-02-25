package authz

import (
	"context"
	"fmt"
	"strings"

	app "github.com/kaitobq/oauth21-oidc-idp/backend/internal/application/organization"
)

const (
	ScopeOrganizationRead  = "organization.read"
	ScopeOrganizationWrite = "organization.write"
	ScopeOrganizationAdmin = "organization.admin"
)

// ScopeGateway authorizes actions based on actor subject and scopes.
type ScopeGateway struct{}

var _ app.AuthzGateway = (*ScopeGateway)(nil)

func NewScopeGateway() *ScopeGateway {
	return &ScopeGateway{}
}

func (g *ScopeGateway) AuthorizeCreateOrganization(_ context.Context, actor *app.Actor) error {
	if err := ensureAuthenticatedActor(actor); err != nil {
		return err
	}
	if actor.HasScope(ScopeOrganizationAdmin) || actor.HasScope(ScopeOrganizationWrite) {
		return nil
	}
	return fmt.Errorf("%w: missing %s", app.ErrPermissionDenied, ScopeOrganizationWrite)
}

func (g *ScopeGateway) AuthorizeGetOrganization(_ context.Context, actor *app.Actor) error {
	if err := ensureAuthenticatedActor(actor); err != nil {
		return err
	}
	if actor.HasScope(ScopeOrganizationAdmin) || actor.HasScope(ScopeOrganizationRead) {
		return nil
	}
	return fmt.Errorf("%w: missing %s", app.ErrPermissionDenied, ScopeOrganizationRead)
}

func (g *ScopeGateway) AuthorizeListOrganizations(_ context.Context, actor *app.Actor) error {
	if err := ensureAuthenticatedActor(actor); err != nil {
		return err
	}
	if actor.HasScope(ScopeOrganizationAdmin) || actor.HasScope(ScopeOrganizationRead) {
		return nil
	}
	return fmt.Errorf("%w: missing %s", app.ErrPermissionDenied, ScopeOrganizationRead)
}

func ensureAuthenticatedActor(actor *app.Actor) error {
	if actor == nil || strings.TrimSpace(actor.Subject) == "" || strings.EqualFold(strings.TrimSpace(actor.Subject), "anonymous") {
		return app.ErrUnauthenticated
	}
	return nil
}
