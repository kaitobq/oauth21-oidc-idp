package organization

import (
	"context"
	"fmt"

	domain "github.com/kaitobq/oauth21-oidc-idp/backend/internal/domain/organization"
)

type CreateInput struct {
	Name        string
	DisplayName string
}

func (f *Facade) Create(ctx context.Context, in *CreateInput) (*DTO, error) {
	name, err := domain.NewName(in.Name)
	if err != nil {
		return nil, fmt.Errorf("invalid name: %w", err)
	}

	displayName, err := domain.NewDisplayName(in.DisplayName)
	if err != nil {
		return nil, fmt.Errorf("invalid display name: %w", err)
	}

	entity := domain.NewEntity(name, displayName)
	if err := f.repo.Save(ctx, entity); err != nil {
		return nil, fmt.Errorf("save organization: %w", err)
	}

	return toDTO(entity), nil
}
