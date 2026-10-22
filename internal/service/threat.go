package service

import (
	"context"
	"fmt"

	"kasper/internal/domain"
)

type ThreatRepository interface {
	Create(context.Context, domain.Threat) error
	GetByMD5(context.Context, string) (domain.Threat, error)
	Update(context.Context, domain.Threat) error
}

type CreateThreatInput struct {
	MD5         string
	Name        string
	Description string
	Severity    *string
}

type UpdateThreatInput struct {
	Name        string
	Description string
	Severity    *string
}

type ThreatService struct {
	repository ThreatRepository
}

func NewThreatService(repository ThreatRepository) *ThreatService {
	return &ThreatService{repository: repository}
}

func (s *ThreatService) Create(ctx context.Context, input CreateThreatInput) (domain.Threat, error) {
	md5, err := domain.NormalizeMD5(input.MD5)
	if err != nil {
		return domain.Threat{}, err
	}
	severity, err := resolveSeverity(input.Severity)
	if err != nil {
		return domain.Threat{}, err
	}
	if err := domain.ValidateThreatText(input.Name, input.Description); err != nil {
		return domain.Threat{}, err
	}
	item := domain.Threat{
		MD5:         md5,
		Name:        input.Name,
		Description: input.Description,
		Severity:    severity,
	}
	if err := s.repository.Create(ctx, item); err != nil {
		return domain.Threat{}, fmt.Errorf("create threat: %w", err)
	}
	return item, nil
}

func (s *ThreatService) GetByMD5(ctx context.Context, md5 string) (domain.Threat, error) {
	md5, err := domain.NormalizeMD5(md5)
	if err != nil {
		return domain.Threat{}, err
	}
	item, err := s.repository.GetByMD5(ctx, md5)
	if err != nil {
		return domain.Threat{}, fmt.Errorf("get threat: %w", err)
	}
	return item, nil
}

func (s *ThreatService) Update(ctx context.Context, md5 string, input UpdateThreatInput) (domain.Threat, error) {
	md5, err := domain.NormalizeMD5(md5)
	if err != nil {
		return domain.Threat{}, err
	}
	severity, err := resolveSeverity(input.Severity)
	if err != nil {
		return domain.Threat{}, err
	}
	if err := domain.ValidateThreatText(input.Name, input.Description); err != nil {
		return domain.Threat{}, err
	}
	item := domain.Threat{
		MD5:         md5,
		Name:        input.Name,
		Description: input.Description,
		Severity:    severity,
	}
	if err := s.repository.Update(ctx, item); err != nil {
		return domain.Threat{}, fmt.Errorf("update threat: %w", err)
	}
	return item, nil
}

func resolveSeverity(value *string) (domain.Severity, error) {
	if value == nil {
		return domain.SeverityUnknown, nil
	}
	return domain.ParseSeverity(*value)
}
