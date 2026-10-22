package integration_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"kasper/internal/database"
	"kasper/internal/domain"
	"kasper/internal/repository/postgres"
)

func TestPostgresMigrationsAreIdempotent(t *testing.T) {
	pool, _ := newPostgresPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	repository := postgres.NewThreatRepository(pool)
	want := domain.Threat{MD5: md5, Name: "keep across migration runs", Severity: domain.SeverityLow}
	if err := repository.Create(ctx, want); err != nil {
		t.Fatal(err)
	}
	if err := database.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("reapplying migrations: %v", err)
	}
	got, err := repository.GetByMD5(ctx, md5)
	if err != nil || got != want {
		t.Fatalf("data after repeated migration = %+v, %v; want %+v", got, err, want)
	}
}

func TestPostgresRepository(t *testing.T) {
	pool, _ := newPostgresPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	repository := postgres.NewThreatRepository(pool)
	want := domain.Threat{
		MD5:         md5,
		Name:        `'); DROP TABLE threats; -- Проверка`,
		Description: "Quotes: ' and \"; backslash: \\; newline:\nЮникод 🔒",
		Severity:    domain.SeverityHigh,
	}
	if err := repository.Create(ctx, want); err != nil {
		t.Fatal(err)
	}
	duplicate := want
	duplicate.Name = "must not overwrite"
	if err := repository.Create(ctx, duplicate); !errors.Is(err, domain.ErrThreatAlreadyExists) {
		t.Errorf("duplicate error = %v, want ErrThreatAlreadyExists", err)
	}
	got, err := repository.GetByMD5(ctx, md5)
	if err != nil || got != want {
		t.Fatalf("stored threat = %+v, %v; want %+v", got, err, want)
	}
	if _, err := repository.GetByMD5(ctx, otherMD5); !errors.Is(err, domain.ErrThreatNotFound) {
		t.Errorf("missing read error = %v, want ErrThreatNotFound", err)
	}
	missing := domain.Threat{MD5: otherMD5, Name: "missing", Severity: domain.SeverityUnknown}
	if err := repository.Update(ctx, missing); !errors.Is(err, domain.ErrThreatNotFound) {
		t.Errorf("missing update error = %v, want ErrThreatNotFound", err)
	}
	if _, err := repository.GetByMD5(ctx, otherMD5); !errors.Is(err, domain.ErrThreatNotFound) {
		t.Errorf("missing update created a record: %v", err)
	}
	want.Name, want.Description, want.Severity = "updated ' имя", "replacement \\ description", domain.SeverityCritical
	if err := repository.Update(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err = repository.GetByMD5(ctx, md5)
	if err != nil || got != want {
		t.Fatalf("updated threat = %+v, %v; want %+v", got, err, want)
	}

	canceled, stop := context.WithCancel(ctx)
	stop()
	if err := repository.Create(canceled, missing); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled create error = %v, want context.Canceled", err)
	}
	if _, err := repository.GetByMD5(canceled, md5); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled read error = %v, want context.Canceled", err)
	}
	if err := repository.Update(canceled, duplicate); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled update error = %v, want context.Canceled", err)
	}
	got, err = repository.GetByMD5(ctx, md5)
	if err != nil || got != want {
		t.Errorf("canceled update changed data: %+v, %v", got, err)
	}
	if _, err := repository.GetByMD5(ctx, otherMD5); !errors.Is(err, domain.ErrThreatNotFound) {
		t.Errorf("canceled create inserted data: %v", err)
	}
}

func TestPostgresConstraintsAndDefaults(t *testing.T) {
	pool, _ := newPostgresPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tests := []struct {
		name                              string
		md5, title, description, severity any
		code                              string
	}{
		{"invalid MD5", "invalid", "test", "", "unknown", "23514"},
		{"uppercase MD5", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "test", "", "unknown", "23514"},
		{"invalid severity", md5, "test", "", "urgent", "23514"},
		{"null MD5", nil, "test", "", "unknown", "23502"},
		{"null name", md5, nil, "", "unknown", "23502"},
		{"null description", md5, "test", nil, "unknown", "23502"},
		{"null severity", md5, "test", "", nil, "23502"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pool.Exec(ctx, "INSERT INTO threats (md5, name, description, severity) VALUES ($1, $2, $3, $4)", tt.md5, tt.title, tt.description, tt.severity)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != tt.code {
				t.Errorf("constraint error = %v, want PostgreSQL code %s", err, tt.code)
			}
		})
	}
	if _, err := pool.Exec(ctx, "INSERT INTO threats (md5, name) VALUES ($1, $2)", md5, ""); err != nil {
		t.Fatalf("insert using database defaults: %v", err)
	}
	want := domain.Threat{MD5: md5, Severity: domain.SeverityUnknown}
	got, err := postgres.NewThreatRepository(pool).GetByMD5(ctx, md5)
	if err != nil || got != want {
		t.Errorf("database defaults = %+v, %v; want %+v", got, err, want)
	}
}

func TestPostgresPersistsAfterServerAndPoolRecreation(t *testing.T) {
	pool, config := newPostgresPool(t)
	server := newServerWithRepository(t, postgres.NewThreatRepository(pool))
	request(t, server, "POST", "/info", `{"md5":"`+md5+`","name":"persisted","description":"stored in PostgreSQL","severity":"high"}`, 201)
	server.Close()
	pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reopened, err := pgxpool.NewWithConfig(ctx, config.Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Close)
	if err := database.ApplyMigrations(ctx, reopened); err != nil {
		t.Fatal(err)
	}
	server = newServerWithRepository(t, postgres.NewThreatRepository(reopened))
	want := threat{MD5: md5, Name: "persisted", Description: "stored in PostgreSQL", Severity: "high"}
	assertThreat(t, request(t, server, "GET", "/info/"+md5, "", 200), want)
	want.Name, want.Description, want.Severity = "updated after restart", "", "unknown"
	assertThreat(t, request(t, server, "PUT", "/info/"+md5, `{"name":"updated after restart"}`, 200), want)
	assertThreat(t, request(t, server, "GET", "/info/"+md5, "", 200), want)
}

func newPostgresPool(t *testing.T) (*pgxpool.Pool, *pgxpool.Config) {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set TEST_DATABASE_URL to run PostgreSQL integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	admin, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect to test PostgreSQL: %v", err)
	}
	t.Cleanup(admin.Close)
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	schema := "kasper_test_" + hex.EncodeToString(random[:])
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatalf("create isolated test schema: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop isolated test schema: %v", err)
		}
	})
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("migrate isolated test schema: %v", err)
	}
	return pool, config
}
