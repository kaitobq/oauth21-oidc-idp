package organization

import (
	"context"
	"fmt"

	domain "github.com/kaitobq/oauth21-oidc-idp/backend/internal/domain/organization"
)

func (f *Facade) Get(ctx context.Context, id string) (*DTO, error) {
	orgID, err := domain.ParseID(id)
	if err != nil {
		return nil, fmt.Errorf("invalid id: %w", err)
	}

	entity, err := f.repo.FindByID(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("find organization: %w", err)
	}

	return toDTO(entity), nil
}

type ListOutput struct {
	Organizations []*DTO
	NextPageToken string
}

func (f *Facade) List(ctx context.Context, pageSize int, pageToken string) (*ListOutput, error) {
	entities, nextToken, err := f.repo.List(ctx, pageSize, pageToken)
	if err != nil {
		return nil, fmt.Errorf("list organizations: %w", err)
	}

	dtos := make([]*DTO, len(entities))
	for i, e := range entities {
		dtos[i] = toDTO(e)
	}

	return &ListOutput{
		Organizations: dtos,
		NextPageToken: nextToken,
	}, nil
}
