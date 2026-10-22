package memory_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"kasper/internal/domain"
	"kasper/internal/repository/memory"
)

const testMD5 = "d41d8cd98f00b204e9800998ecf8427e"

func TestRepositoryLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := memory.NewThreatRepository()
	original := domain.Threat{MD5: testMD5, Name: "original", Description: "details", Severity: domain.SeverityHigh}
	input := original
	if err := repo.Create(ctx, input); err != nil {
		t.Fatal(err)
	}
	input.Name = "duplicate"
	if err := repo.Create(ctx, input); !errors.Is(err, domain.ErrThreatAlreadyExists) {
		t.Fatalf("duplicate Create error = %v; want ErrThreatAlreadyExists", err)
	}
	got, err := repo.GetByMD5(ctx, testMD5)
	if err != nil || got != original {
		t.Fatalf("duplicate changed original: got %+v, %v; want %+v", got, err, original)
	}
	got.Name = "changed returned copy"
	if again, err := repo.GetByMD5(ctx, testMD5); err != nil || again != original {
		t.Fatalf("changing returned value changed storage: got %+v, %v", again, err)
	}
	replacement := domain.Threat{MD5: testMD5, Severity: domain.SeverityUnknown}
	if err := repo.Update(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	if got, err := repo.GetByMD5(ctx, testMD5); err != nil || got != replacement {
		t.Fatalf("Update did not replace fields: got %+v, %v; want %+v", got, err, replacement)
	}
}

func TestMissingUpdateDoesNotInsert(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := memory.NewThreatRepository()
	item := domain.Threat{MD5: testMD5, Name: "missing"}
	if err := repo.Update(ctx, item); !errors.Is(err, domain.ErrThreatNotFound) {
		t.Fatalf("Update error = %v; want ErrThreatNotFound", err)
	}
	if got, err := repo.GetByMD5(ctx, testMD5); !errors.Is(err, domain.ErrThreatNotFound) || got != (domain.Threat{}) {
		t.Fatalf("missing GetByMD5 = %+v, %v; want empty threat and ErrThreatNotFound", got, err)
	}
	if err := repo.Create(ctx, item); err != nil {
		t.Fatalf("Create after missing Update failed: %v", err)
	}
}

func TestCanceledContextDoesNotChangeStorage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := memory.NewThreatRepository()
	original := domain.Threat{MD5: testMD5, Name: "original", Severity: domain.SeverityLow}
	if err := repo.Create(ctx, original); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	newItem := domain.Threat{MD5: "00000000000000000000000000000000", Name: "new"}
	if err := repo.Create(canceled, newItem); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Create error = %v", err)
	}
	if err := repo.Update(canceled, domain.Threat{MD5: testMD5, Name: "changed"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Update error = %v", err)
	}
	if got, err := repo.GetByMD5(canceled, testMD5); !errors.Is(err, context.Canceled) || got != (domain.Threat{}) {
		t.Fatalf("canceled GetByMD5 = %+v, %v", got, err)
	}
	if got, err := repo.GetByMD5(ctx, testMD5); err != nil || got != original {
		t.Fatalf("canceled Update changed original: %+v, %v", got, err)
	}
	if _, err := repo.GetByMD5(ctx, newItem.MD5); !errors.Is(err, domain.ErrThreatNotFound) {
		t.Fatalf("canceled Create inserted item: %v", err)
	}
}

func TestConcurrentCreateHasExactlyOneWinner(t *testing.T) {
	t.Parallel()
	const workers = 32
	ctx := context.Background()
	repo := memory.NewThreatRepository()
	start := make(chan struct{})
	type result struct {
		item domain.Threat
		err  error
	}
	results := make(chan result, workers)
	for i := range workers {
		go func() {
			item := domain.Threat{MD5: testMD5, Name: fmt.Sprintf("candidate %d", i)}
			<-start
			results <- result{item: item, err: repo.Create(ctx, item)}
		}()
	}
	close(start)
	winners, duplicates := 0, 0
	var winner domain.Threat
	for range workers {
		result := <-results
		switch {
		case result.err == nil:
			winners++
			winner = result.item
		case errors.Is(result.err, domain.ErrThreatAlreadyExists):
			duplicates++
		default:
			t.Errorf("unexpected Create error: %v", result.err)
		}
	}
	if winners != 1 || duplicates != workers-1 {
		t.Fatalf("winners = %d, duplicates = %d; want 1 and %d", winners, duplicates, workers-1)
	}
	if got, err := repo.GetByMD5(ctx, testMD5); err != nil || got != winner {
		t.Fatalf("stored item = %+v, %v; want winner %+v", got, err, winner)
	}
}

func TestConcurrentReadAndUpdate(t *testing.T) {
	t.Parallel()
	const workers, iterations = 8, 100
	ctx := context.Background()
	repo := memory.NewThreatRepository()
	if err := repo.Create(ctx, domain.Threat{MD5: testMD5, Name: "initial", Description: "initial"}); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for worker := range workers {
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			for iteration := range iterations {
				value := fmt.Sprintf("%d/%d", worker, iteration)
				item := domain.Threat{MD5: testMD5, Name: value, Description: value}
				if err := repo.Update(ctx, item); err != nil {
					t.Errorf("concurrent Update: %v", err)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			for range iterations {
				item, err := repo.GetByMD5(ctx, testMD5)
				if err != nil || item.MD5 != testMD5 || item.Name != item.Description {
					t.Errorf("inconsistent concurrent read: %+v, %v", item, err)
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()
}
