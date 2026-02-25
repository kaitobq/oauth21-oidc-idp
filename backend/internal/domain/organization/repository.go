package organization

import "context"

// Repository defines the persistence interface for Organization.
// Implementations live in the infra layer.
type Repository interface {
	Save(ctx context.Context, entity *Entity) error
	FindByID(ctx context.Context, id ID) (*Entity, error)
	List(ctx context.Context, pageSize int, pageToken string) ([]*Entity, string, error)
}
