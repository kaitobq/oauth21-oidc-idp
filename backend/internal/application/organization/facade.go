package organization

import (
	domain "github.com/kaitobq/oauth21-oidc-idp/backend/internal/domain/organization"
)

// Facade aggregates command and query use cases for Organization.
type Facade struct {
	repo domain.Repository
}

// NewFacade creates a new Organization facade.
func NewFacade(repo domain.Repository) *Facade {
	return &Facade{repo: repo}
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
