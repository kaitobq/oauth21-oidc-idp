package organization

import (
	"context"
	"database/sql"
	"fmt"

	domain "github.com/kaitobq/oauth21-oidc-idp/backend/internal/domain/organization"
)

// MySQLRepository implements domain.Repository using MySQL.
type MySQLRepository struct {
	db *sql.DB
}

var _ domain.Repository = (*MySQLRepository)(nil)

// NewMySQLRepository creates a new MySQL-backed Organization repository.
func NewMySQLRepository(db *sql.DB) *MySQLRepository {
	return &MySQLRepository{db: db}
}

func (r *MySQLRepository) Save(ctx context.Context, entity *domain.Entity) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO organizations (id, name, display_name, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE name=VALUES(name), display_name=VALUES(display_name), updated_at=VALUES(updated_at)`,
		entity.ID.String(), entity.Name.String(), entity.DisplayName.String(),
		entity.CreatedAt, entity.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("save organization: %w", err)
	}
	return nil
}

func (r *MySQLRepository) FindByID(ctx context.Context, id domain.ID) (*domain.Entity, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, name, display_name, created_at, updated_at FROM organizations WHERE id = ?`,
		id.String(),
	)

	var e domain.Entity
	var idStr, nameStr, displayNameStr string
	if err := row.Scan(&idStr, &nameStr, &displayNameStr, &e.CreatedAt, &e.UpdatedAt); err != nil {
		return nil, fmt.Errorf("find organization: %w", err)
	}

	e.ID = domain.ID(idStr)
	e.Name = domain.Name(nameStr)
	e.DisplayName = domain.DisplayName(displayNameStr)
	return &e, nil
}

func (r *MySQLRepository) List(ctx context.Context, pageSize int, pageToken string) ([]*domain.Entity, string, error) {
	if pageSize <= 0 {
		pageSize = 20
	}

	query := `SELECT id, name, display_name, created_at, updated_at FROM organizations`
	args := []any{}

	if pageToken != "" {
		query += ` WHERE id > ?`
		args = append(args, pageToken)
	}
	query += ` ORDER BY id LIMIT ?`
	args = append(args, pageSize+1)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, "", fmt.Errorf("list organizations: %w", err)
	}
	defer rows.Close()

	var entities []*domain.Entity
	for rows.Next() {
		var e domain.Entity
		var idStr, nameStr, displayNameStr string
		if err := rows.Scan(&idStr, &nameStr, &displayNameStr, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, "", fmt.Errorf("scan organization: %w", err)
		}
		e.ID = domain.ID(idStr)
		e.Name = domain.Name(nameStr)
		e.DisplayName = domain.DisplayName(displayNameStr)
		entities = append(entities, &e)
	}

	var nextToken string
	if len(entities) > pageSize {
		nextToken = entities[pageSize].ID.String()
		entities = entities[:pageSize]
	}

	return entities, nextToken, nil
}
