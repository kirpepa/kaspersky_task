package memory

import (
	"context"
	"sync"

	"kasper/internal/domain"
)

type ThreatRepository struct {
	mu      sync.RWMutex
	threats map[string]domain.Threat
}

func NewThreatRepository() *ThreatRepository {
	return &ThreatRepository{threats: make(map[string]domain.Threat)}
}

func (r *ThreatRepository) Create(ctx context.Context, item domain.Threat) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, exists := r.threats[item.MD5]; exists {
		return domain.ErrThreatAlreadyExists
	}
	r.threats[item.MD5] = item
	return nil
}

func (r *ThreatRepository) GetByMD5(ctx context.Context, md5 string) (domain.Threat, error) {
	if err := ctx.Err(); err != nil {
		return domain.Threat{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return domain.Threat{}, err
	}
	item, exists := r.threats[md5]
	if !exists {
		return domain.Threat{}, domain.ErrThreatNotFound
	}
	return item, nil
}

func (r *ThreatRepository) Update(ctx context.Context, item domain.Threat) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, exists := r.threats[item.MD5]; !exists {
		return domain.ErrThreatNotFound
	}
	r.threats[item.MD5] = item
	return nil
}
