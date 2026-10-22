package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"kasper/internal/domain"
)

// OperationTimeout includes acquiring a pool connection and executing the query.
const OperationTimeout = 3 * time.Second

type ThreatRepository struct {
	pool *pgxpool.Pool
}

func NewThreatRepository(pool *pgxpool.Pool) *ThreatRepository {
	return &ThreatRepository{pool: pool}
}

func (r *ThreatRepository) Create(ctx context.Context, item domain.Threat) error {
	ctx, cancel := context.WithTimeout(ctx, OperationTimeout)
	defer cancel()
	_, err := r.pool.Exec(ctx,
		`INSERT INTO threats (md5, name, description, severity) VALUES ($1, $2, $3, $4)`,
		item.MD5, item.Name, item.Description, string(item.Severity),
	)
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			return domain.ErrThreatAlreadyExists
		}
		return fmt.Errorf("insert threat: %w", err)
	}
	return nil
}

func (r *ThreatRepository) GetByMD5(ctx context.Context, md5 string) (domain.Threat, error) {
	ctx, cancel := context.WithTimeout(ctx, OperationTimeout)
	defer cancel()
	var item domain.Threat
	var severity string
	err := r.pool.QueryRow(ctx,
		`SELECT md5, name, description, severity FROM threats WHERE md5 = $1`, md5,
	).Scan(&item.MD5, &item.Name, &item.Description, &severity)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Threat{}, domain.ErrThreatNotFound
		}
		return domain.Threat{}, fmt.Errorf("select threat: %w", err)
	}
	item.Severity = domain.Severity(severity)
	return item, nil
}

func (r *ThreatRepository) Update(ctx context.Context, item domain.Threat) error {
	ctx, cancel := context.WithTimeout(ctx, OperationTimeout)
	defer cancel()
	result, err := r.pool.Exec(ctx,
		`UPDATE threats SET name = $2, description = $3, severity = $4 WHERE md5 = $1`,
		item.MD5, item.Name, item.Description, string(item.Severity),
	)
	if err != nil {
		return fmt.Errorf("update threat: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domain.ErrThreatNotFound
	}
	return nil
}
