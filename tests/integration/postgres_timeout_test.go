package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"kasper/internal/domain"
	"kasper/internal/repository/postgres"
)

func TestPostgresOperationsTimeOutWhileWaitingForTableLock(t *testing.T) {
	for _, operation := range postgresTimeoutOperations() {
		for _, useParentDeadline := range []bool{false, true} {
			name := operation.name + "/repository deadline"
			if useParentDeadline {
				name = operation.name + "/earlier parent deadline"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				pool, _ := newPostgresPool(t)
				repository := postgres.NewThreatRepository(pool)
				original := seedTimeoutThreat(t, repository)
				lockContext, stopLock := context.WithTimeout(context.Background(), 15*time.Second)
				defer stopLock()
				transaction, err := pool.Begin(lockContext)
				if err != nil {
					t.Fatal(err)
				}
				defer transaction.Rollback(context.Background())
				if _, err := transaction.Exec(lockContext, "LOCK TABLE threats IN ACCESS EXCLUSIVE MODE"); err != nil {
					t.Fatal(err)
				}
				assertPostgresOperationTimeout(t, repository, operation.run, useParentDeadline)
				if err := transaction.Rollback(lockContext); err != nil {
					t.Fatal(err)
				}
				assertTimeoutDataPreserved(t, repository, original)
			})
		}
	}
}

func TestPostgresOperationsTimeOutWhileWaitingForPoolConnection(t *testing.T) {
	for _, operation := range postgresTimeoutOperations() {
		t.Run(operation.name, func(t *testing.T) {
			t.Parallel()
			pool, config := newPostgresPool(t)
			repository := postgres.NewThreatRepository(pool)
			original := seedTimeoutThreat(t, repository)
			acquireContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			held := make([]*pgxpool.Conn, 0, config.MaxConns)
			defer func() {
				for _, connection := range held {
					connection.Release()
				}
			}()
			for range config.MaxConns {
				connection, err := pool.Acquire(acquireContext)
				if err != nil {
					t.Fatal(err)
				}
				held = append(held, connection)
			}
			assertPostgresOperationTimeout(t, repository, operation.run, false)
			for _, connection := range held {
				connection.Release()
			}
			held = nil
			assertTimeoutDataPreserved(t, repository, original)
		})
	}
}

type postgresTimeoutOperation struct {
	name string
	run  func(context.Context, *postgres.ThreatRepository) error
}

func postgresTimeoutOperations() []postgresTimeoutOperation {
	return []postgresTimeoutOperation{
		{"create", func(ctx context.Context, repository *postgres.ThreatRepository) error {
			return repository.Create(ctx, domain.Threat{MD5: otherMD5, Name: "must not be inserted", Severity: domain.SeverityUnknown})
		}},
		{"get", func(ctx context.Context, repository *postgres.ThreatRepository) error {
			_, err := repository.GetByMD5(ctx, md5)
			return err
		}},
		{"update", func(ctx context.Context, repository *postgres.ThreatRepository) error {
			return repository.Update(ctx, domain.Threat{MD5: md5, Name: "must not replace original", Severity: domain.SeverityCritical})
		}},
	}
}

func assertPostgresOperationTimeout(t *testing.T, repository *postgres.ThreatRepository, operation func(context.Context, *postgres.ThreatRepository) error, earlierParent bool) {
	t.Helper()
	// The outer deadline bounds a regression that removes repository timeouts.
	parentTimeout := postgres.OperationTimeout + 5*time.Second
	wantTimeout := postgres.OperationTimeout
	if earlierParent {
		parentTimeout = 250 * time.Millisecond
		wantTimeout = parentTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), parentTimeout)
	defer cancel()
	started := time.Now()
	err := operation(ctx, repository)
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("operation error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > wantTimeout+2*time.Second {
		t.Fatalf("operation took %s; configured deadline was %s", elapsed, wantTimeout)
	}
	if !earlierParent && ctx.Err() != nil {
		t.Fatalf("operation waited until the later parent deadline: %v", ctx.Err())
	}
}

func seedTimeoutThreat(t *testing.T, repository *postgres.ThreatRepository) domain.Threat {
	t.Helper()
	original := domain.Threat{MD5: md5, Name: "original", Description: "preserved after timeout", Severity: domain.SeverityLow}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := repository.Create(ctx, original); err != nil {
		t.Fatal(err)
	}
	return original
}

func assertTimeoutDataPreserved(t *testing.T, repository *postgres.ThreatRepository, original domain.Threat) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := repository.GetByMD5(ctx, md5)
	if err != nil || got != original {
		t.Fatalf("record after timeout = %+v, %v; want %+v", got, err, original)
	}
	if _, err := repository.GetByMD5(ctx, otherMD5); !errors.Is(err, domain.ErrThreatNotFound) {
		t.Fatalf("timed-out create left a record: %v", err)
	}
}
