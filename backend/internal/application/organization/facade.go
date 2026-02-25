package organization

import (
	"context"

	domain "github.com/kaitobq/oauth21-oidc-idp/backend/internal/domain/organization"
)

// Facade aggregates command and query use cases for Organization.
type Facade struct {
	command CommandService
	query   QueryService
	authz   AuthzGateway
}

// Actor is the authenticated caller context used by authorization checks.
type Actor struct {
	Subject string
}

// AuthzGateway checks permissions before use case execution.
type AuthzGateway interface {
	AuthorizeCreateOrganization(ctx context.Context, actor *Actor) error
	AuthorizeGetOrganization(ctx context.Context, actor *Actor) error
	AuthorizeListOrganizations(ctx context.Context, actor *Actor) error
}

// CommandService defines write-side use cases.
type CommandService interface {
	Create(ctx context.Context, in *CreateInput) (*DTO, error)
}

// QueryService defines read-side use cases.
type QueryService interface {
	Get(ctx context.Context, id domain.ID) (*DTO, error)
	List(ctx context.Context, pageSize int, pageToken string) (*ListOutput, error)
}

// NewFacade creates a new Organization facade.
func NewFacade(command CommandService, query QueryService, authz AuthzGateway) *Facade {
	return &Facade{
		command: command,
		query:   query,
		authz:   authz,
	}
}

func (f *Facade) Create(ctx context.Context, actor *Actor, in *CreateInput) (*DTO, error) {
	if err := f.authz.AuthorizeCreateOrganization(ctx, actor); err != nil {
		return nil, err
	}
	return f.command.Create(ctx, in)
}

func (f *Facade) Get(ctx context.Context, actor *Actor, id domain.ID) (*DTO, error) {
	if err := f.authz.AuthorizeGetOrganization(ctx, actor); err != nil {
		return nil, err
	}
	return f.query.Get(ctx, id)
}

func (f *Facade) List(ctx context.Context, actor *Actor, pageSize int, pageToken string) (*ListOutput, error) {
	if err := f.authz.AuthorizeListOrganizations(ctx, actor); err != nil {
		return nil, err
	}
	return f.query.List(ctx, pageSize, pageToken)
}

func toDTO(e *domain.Entity) *DTO {
	return &DTO{
		ID:          e.ID.String(),
		Name:        e.Name.String(),
		DisplayName: e.DisplayName.String(),
		CreatedAt:   e.CreatedAt,
		UpdatedAt:   e.UpdatedAt,
	}
}
