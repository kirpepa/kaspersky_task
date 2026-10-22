package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-migrate/migrate/v4"
	migratepostgres "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"kasper/migrations"
)

func ApplyMigrations(ctx context.Context, pool *pgxpool.Pool) (result error) {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}

	// A separate connection keeps migration timeouts out of the application pool.
	config := pool.Config().ConnConfig.Copy()
	if config.RuntimeParams == nil {
		config.RuntimeParams = make(map[string]string)
	}
	config.RuntimeParams["lock_timeout"] = "10s"
	config.RuntimeParams["statement_timeout"] = "30s"
	if config.ConnectTimeout == 0 || config.ConnectTimeout > 10*time.Second {
		config.ConnectTimeout = 10 * time.Second
	}
	db := stdlib.OpenDB(*config)
	defer func() {
		if err := db.Close(); err != nil {
			result = errors.Join(result, fmt.Errorf("close migration database: %w", err))
		}
	}()
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("connect for migrations: %w", err)
	}
	defer conn.Close()

	// WithConnection keeps ownership explicit even if driver initialization fails.
	driver, err := migratepostgres.WithConnection(ctx, conn, &migratepostgres.Config{
		StatementTimeout: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("initialize migration database: %w", err)
	}
	source, err := iofs.New(migrations.Files, ".")
	if err != nil {
		return fmt.Errorf("open embedded migrations: %w", err)
	}
	migrator, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
	if err != nil {
		source.Close()
		return fmt.Errorf("initialize migrations: %w", err)
	}
	defer func() {
		sourceErr, databaseErr := migrator.Close()
		if err := errors.Join(sourceErr, databaseErr); err != nil {
			result = errors.Join(result, fmt.Errorf("close migrations: %w", err))
		}
	}()
	migrator.LockTimeout = 15 * time.Second
	stop := context.AfterFunc(ctx, func() { migrator.GracefulStop <- true })
	defer stop()

	err = migrator.Up()
	if errors.Is(err, migrate.ErrNoChange) {
		err = nil
	}
	if err = errors.Join(err, ctx.Err()); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}
