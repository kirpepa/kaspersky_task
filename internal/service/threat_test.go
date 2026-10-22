package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"kasper/internal/domain"
	"kasper/internal/service"
)

const testMD5 = "d41d8cd98f00b204e9800998ecf8427e"

type repositoryStub struct {
	err       error
	result    domain.Threat
	calls     int
	operation string
	ctx       context.Context
	item      domain.Threat
	md5       string
}

func (r *repositoryStub) Create(ctx context.Context, item domain.Threat) error {
	r.calls++
	r.operation, r.ctx, r.item = "create", ctx, item
	return r.err
}

func (r *repositoryStub) GetByMD5(ctx context.Context, md5 string) (domain.Threat, error) {
	r.calls++
	r.operation, r.ctx, r.md5 = "get", ctx, md5
	return r.result, r.err
}

func (r *repositoryStub) Update(ctx context.Context, item domain.Threat) error {
	r.calls++
	r.operation, r.ctx, r.item = "update", ctx, item
	return r.err
}

type serviceCall func(context.Context, *service.ThreatService) (domain.Threat, error)

func TestThreatServiceRequests(t *testing.T) {
	t.Parallel()
	critical := "critical"
	stored := domain.Threat{MD5: testMD5, Name: "stored", Description: "original", Severity: domain.SeverityHigh}
	tests := []struct {
		name, operation string
		call            serviceCall
		want            domain.Threat
	}{
		{
			name: "create normalizes MD5 and defaults severity", operation: "create",
			call: func(ctx context.Context, s *service.ThreatService) (domain.Threat, error) {
				return s.Create(ctx, service.CreateThreatInput{MD5: strings.ToUpper(testMD5), Description: "description"})
			},
			want: domain.Threat{MD5: testMD5, Description: "description", Severity: domain.SeverityUnknown},
		},
		{
			name: "create preserves explicit fields", operation: "create",
			call: func(ctx context.Context, s *service.ThreatService) (domain.Threat, error) {
				return s.Create(ctx, service.CreateThreatInput{MD5: testMD5, Name: " name ", Description: "details", Severity: &critical})
			},
			want: domain.Threat{MD5: testMD5, Name: " name ", Description: "details", Severity: domain.SeverityCritical},
		},
		{
			name: "get normalizes MD5 and returns repository result", operation: "get",
			call: func(ctx context.Context, s *service.ThreatService) (domain.Threat, error) {
				return s.GetByMD5(ctx, strings.ToUpper(testMD5))
			},
			want: stored,
		},
		{
			name: "update replaces fields and restores defaults", operation: "update",
			call: func(ctx context.Context, s *service.ThreatService) (domain.Threat, error) {
				return s.Update(ctx, strings.ToUpper(testMD5), service.UpdateThreatInput{})
			},
			want: domain.Threat{MD5: testMD5, Severity: domain.SeverityUnknown},
		},
		{
			name: "update preserves explicit fields", operation: "update",
			call: func(ctx context.Context, s *service.ThreatService) (domain.Threat, error) {
				return s.Update(ctx, testMD5, service.UpdateThreatInput{Name: "new", Description: "replacement", Severity: &critical})
			},
			want: domain.Threat{MD5: testMD5, Name: "new", Description: "replacement", Severity: domain.SeverityCritical},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &repositoryStub{result: stored}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			got, err := tt.call(ctx, service.NewThreatService(repo))
			if err != nil || got != tt.want {
				t.Fatalf("result = %+v, %v; want %+v, nil", got, err, tt.want)
			}
			if repo.calls != 1 || repo.operation != tt.operation || repo.ctx != ctx {
				t.Fatalf("repository call = %q, count %d, same context %t", repo.operation, repo.calls, repo.ctx == ctx)
			}
			if tt.operation == "get" {
				if repo.md5 != testMD5 {
					t.Fatalf("repository MD5 = %q; want %q", repo.md5, testMD5)
				}
			} else if repo.item != tt.want {
				t.Fatalf("repository input = %+v; want %+v", repo.item, tt.want)
			}
		})
	}
}

func TestInvalidInputDoesNotCallRepository(t *testing.T) {
	t.Parallel()
	empty := ""
	tests := []struct {
		name string
		call serviceCall
		want error
	}{
		{"create MD5", func(ctx context.Context, s *service.ThreatService) (domain.Threat, error) {
			return s.Create(ctx, service.CreateThreatInput{MD5: "invalid"})
		}, domain.ErrInvalidMD5},
		{"get MD5", func(ctx context.Context, s *service.ThreatService) (domain.Threat, error) {
			return s.GetByMD5(ctx, "invalid")
		}, domain.ErrInvalidMD5},
		{"update MD5", func(ctx context.Context, s *service.ThreatService) (domain.Threat, error) {
			return s.Update(ctx, "invalid", service.UpdateThreatInput{})
		}, domain.ErrInvalidMD5},
		{"create explicit empty severity", func(ctx context.Context, s *service.ThreatService) (domain.Threat, error) {
			return s.Create(ctx, service.CreateThreatInput{MD5: testMD5, Severity: &empty})
		}, domain.ErrInvalidSeverity},
		{"update explicit empty severity", func(ctx context.Context, s *service.ThreatService) (domain.Threat, error) {
			return s.Update(ctx, testMD5, service.UpdateThreatInput{Severity: &empty})
		}, domain.ErrInvalidSeverity},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &repositoryStub{}
			got, err := tt.call(context.Background(), service.NewThreatService(repo))
			if !errors.Is(err, tt.want) || got != (domain.Threat{}) {
				t.Fatalf("result = %+v, %v; want empty threat and %v", got, err, tt.want)
			}
			if repo.calls != 0 {
				t.Fatalf("invalid input called repository %d times", repo.calls)
			}
		})
	}
}

func TestRepositoryErrorsRemainIdentifiable(t *testing.T) {
	t.Parallel()
	unexpected := errors.New("repository unavailable")
	operations := []struct {
		name     string
		call     serviceCall
		sentinel error
	}{
		{"create", func(ctx context.Context, s *service.ThreatService) (domain.Threat, error) {
			return s.Create(ctx, service.CreateThreatInput{MD5: testMD5})
		}, domain.ErrThreatAlreadyExists},
		{"get", func(ctx context.Context, s *service.ThreatService) (domain.Threat, error) {
			return s.GetByMD5(ctx, testMD5)
		}, domain.ErrThreatNotFound},
		{"update", func(ctx context.Context, s *service.ThreatService) (domain.Threat, error) {
			return s.Update(ctx, testMD5, service.UpdateThreatInput{})
		}, domain.ErrThreatNotFound},
	}
	for _, operation := range operations {
		for _, cause := range []error{operation.sentinel, unexpected, context.Canceled} {
			t.Run(operation.name+"/"+cause.Error(), func(t *testing.T) {
				repo := &repositoryStub{err: cause, result: domain.Threat{Name: "discard on error"}}
				got, err := operation.call(context.Background(), service.NewThreatService(repo))
				if !errors.Is(err, cause) || err == cause || got != (domain.Threat{}) {
					t.Fatalf("result = %+v, %v; want empty threat and wrapped %v", got, err, cause)
				}
				if repo.calls != 1 || repo.operation != operation.name {
					t.Fatalf("repository call = %q, count %d", repo.operation, repo.calls)
				}
			})
		}
	}
}

func TestThreatServiceValidatesTextBeforeRepository(t *testing.T) {
	t.Parallel()
	for _, operation := range []string{"create", "update"} {
		for _, field := range []struct {
			name  string
			limit int
		}{
			{"name", domain.MaxNameLength},
			{"description", domain.MaxDescriptionLength},
		} {
			t.Run(operation+"/"+field.name, func(t *testing.T) {
				tests := []struct {
					name, value string
					invalid     bool
				}{
					{"empty", "", false},
					{"below limit", strings.Repeat("界", field.limit-1), false},
					{"at limit", strings.Repeat("😀", field.limit), false},
					{"over limit", strings.Repeat("界", field.limit+1), true},
					{"NUL", "a\x00b", true},
				}
				for _, tt := range tests {
					t.Run(tt.name, func(t *testing.T) {
						name, description := "valid", "valid"
						if field.name == "name" {
							name = tt.value
						} else {
							description = tt.value
						}
						repo := &repositoryStub{}
						s := service.NewThreatService(repo)
						var got domain.Threat
						var err error
						if operation == "create" {
							got, err = s.Create(context.Background(), service.CreateThreatInput{
								MD5: testMD5, Name: name, Description: description,
							})
						} else {
							got, err = s.Update(context.Background(), testMD5, service.UpdateThreatInput{
								Name: name, Description: description,
							})
						}
						if tt.invalid {
							if !errors.Is(err, domain.ErrInvalidText) || got != (domain.Threat{}) {
								t.Fatalf("invalid text: error = %v, empty result = %t", err, got == (domain.Threat{}))
							}
							if repo.calls != 0 {
								t.Fatalf("invalid text called repository %d times", repo.calls)
							}
							return
						}
						want := domain.Threat{MD5: testMD5, Name: name, Description: description, Severity: domain.SeverityUnknown}
						if err != nil || got != want || repo.item != want || repo.calls != 1 || repo.operation != operation {
							t.Fatalf("valid text: error = %v, returned fields preserved = %t, stored fields preserved = %t, repository calls = %d (%s)",
								err, got == want, repo.item == want, repo.calls, repo.operation)
						}
					})
				}
			})
		}
	}
}
