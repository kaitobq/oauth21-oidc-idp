package organization

import (
	"context"
	"fmt"

	domain "github.com/kaitobq/oauth21-oidc-idp/backend/internal/domain/organization"
)

type CreateInput struct {
	Name        domain.Name
	DisplayName domain.DisplayName
}

type commandService struct {
	repo domain.Repository
}

var _ CommandService = (*commandService)(nil)

// NewCommandService creates the write-side organization use cases.
func NewCommandService(repo domain.Repository) CommandService {
	return &commandService{repo: repo}
}

func (s *commandService) Create(ctx context.Context, in *CreateInput) (*DTO, error) {
	entity := domain.NewEntity(in.Name, in.DisplayName)
	if err := s.repo.Save(ctx, entity); err != nil {
		return nil, fmt.Errorf("save organization: %w", err)
	}

	return toDTO(entity), nil
}
