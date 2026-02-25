package organization

import "time"

// DTO is the data transfer object for Organization.
type DTO struct {
	ID          string
	Name        string
	DisplayName string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
