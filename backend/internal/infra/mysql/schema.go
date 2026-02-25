package mysql

import (
	"context"
	"database/sql"
	"fmt"
)

const createOrganizationsTableSQL = `
CREATE TABLE IF NOT EXISTS organizations (
	id VARCHAR(32) NOT NULL PRIMARY KEY,
	name VARCHAR(63) NOT NULL UNIQUE,
	display_name VARCHAR(255) NOT NULL,
	created_at DATETIME(6) NOT NULL,
	updated_at DATETIME(6) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`

// EnsureOrganizationSchema creates required tables for organization API.
func EnsureOrganizationSchema(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("mysql db is nil")
	}
	if _, err := db.ExecContext(ctx, createOrganizationsTableSQL); err != nil {
		return fmt.Errorf("create organizations table: %w", err)
	}
	return nil
}
