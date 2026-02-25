package authz

import (
	"context"
	"errors"
	"testing"

	app "github.com/kaitobq/oauth21-oidc-idp/backend/internal/application/organization"
)

func TestScopeGatewayAuthorizeCreateOrganization(t *testing.T) {
	t.Parallel()

	gateway := NewScopeGateway()

	t.Run("anonymous actor is rejected", func(t *testing.T) {
		err := gateway.AuthorizeCreateOrganization(context.Background(), app.NewActor("", nil))
		if !errors.Is(err, app.ErrUnauthenticated) {
			t.Fatalf("expected unauthenticated error, got %v", err)
		}
	})

	t.Run("write scope is allowed", func(t *testing.T) {
		err := gateway.AuthorizeCreateOrganization(context.Background(), app.NewActor("alice", []string{ScopeOrganizationWrite}))
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("read scope is rejected", func(t *testing.T) {
		err := gateway.AuthorizeCreateOrganization(context.Background(), app.NewActor("alice", []string{ScopeOrganizationRead}))
		if !errors.Is(err, app.ErrPermissionDenied) {
			t.Fatalf("expected permission denied error, got %v", err)
		}
	})
}

func TestScopeGatewayAuthorizeReadActions(t *testing.T) {
	t.Parallel()

	gateway := NewScopeGateway()
	readActor := app.NewActor("bob", []string{ScopeOrganizationRead})
	adminActor := app.NewActor("admin", []string{ScopeOrganizationAdmin})

	if err := gateway.AuthorizeGetOrganization(context.Background(), readActor); err != nil {
		t.Fatalf("get with read scope must be allowed: %v", err)
	}
	if err := gateway.AuthorizeListOrganizations(context.Background(), readActor); err != nil {
		t.Fatalf("list with read scope must be allowed: %v", err)
	}
	if err := gateway.AuthorizeGetOrganization(context.Background(), adminActor); err != nil {
		t.Fatalf("get with admin scope must be allowed: %v", err)
	}
	if err := gateway.AuthorizeListOrganizations(context.Background(), adminActor); err != nil {
		t.Fatalf("list with admin scope must be allowed: %v", err)
	}
}
