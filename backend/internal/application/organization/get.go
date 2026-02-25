package organization

import (
	"context"
	"fmt"

	domain "github.com/kaitobq/oauth21-oidc-idp/backend/internal/domain/organization"
)

type queryService struct {
	repo domain.Repository
}

var _ QueryService = (*queryService)(nil)

// NewQueryService creates the read-side organization use cases.
func NewQueryService(repo domain.Repository) QueryService {
	return &queryService{repo: repo}
}

func (s *queryService) Get(ctx context.Context, id domain.ID) (*DTO, error) {
	entity, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("find organization: %w", err)
	}

	return toDTO(entity), nil
}

type ListOutput struct {
	Organizations []*DTO
	NextPageToken string
}

func (s *queryService) List(ctx context.Context, pageSize int, pageToken string) (*ListOutput, error) {
	entities, nextToken, err := s.repo.List(ctx, pageSize, pageToken)
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
