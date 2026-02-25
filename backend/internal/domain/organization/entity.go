package organization

import "time"

// Entity represents an Organization in the domain layer.
type Entity struct {
	ID          ID
	Name        Name
	DisplayName DisplayName
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// NewEntity creates a new Organization entity.
func NewEntity(name Name, displayName DisplayName) *Entity {
	now := time.Now()
	return &Entity{
		ID:          NewID(),
		Name:        name,
		DisplayName: displayName,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}
