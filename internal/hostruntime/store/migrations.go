package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sync"

	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

var migrationMu sync.Mutex

func migrateDatabase(ctx context.Context, database *sql.DB, hook func(string) error) error {
	var version int
	if err := database.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > CurrentVersion {
		return ErrIncompatible
	}
	if version == 0 && hook != nil {
		if err := hook("migration_before_commit"); err != nil {
			return err
		}
	}

	// Goose's package configuration is process-global, so serialize configuration
	// and execution across concurrently opened runtime stores.
	migrationMu.Lock()
	defer migrationMu.Unlock()
	goose.SetBaseFS(migrationsFS)
	goose.SetTableName("goose_db_version")
	if err := goose.SetDialect("sqlite3"); err != nil {
		return fmt.Errorf("set store migration dialect: %w", err)
	}
	if err := goose.UpContext(ctx, database, "migrations"); err != nil {
		return fmt.Errorf("migrate runtime store: %w", err)
	}
	return nil
}
