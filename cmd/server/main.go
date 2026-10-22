package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"kasper/internal/config"
	"kasper/internal/database"
	"kasper/internal/repository/postgres"
	"kasper/internal/service"
	httptransport "kasper/internal/transport/http"
)

func main() {
	logger := log.New(os.Stderr, "", log.LstdFlags)
	if err := run(logger); err != nil {
		logger.Fatal(err)
	}
}

func run(logger *log.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	tlsPaths, err := config.LoadTLS()
	if err != nil {
		return err
	}
	tlsConfig, err := httptransport.LoadServerTLS(tlsPaths.CertFile, tlsPaths.KeyFile)
	if err != nil {
		return err
	}
	rateConfig, err := config.LoadRateLimit()
	if err != nil {
		return err
	}
	limiter, err := httptransport.NewIPRateLimiter(rateConfig.RPS, rateConfig.Burst, rateConfig.MaxClients, rateConfig.IdleTTL)
	if err != nil {
		return fmt.Errorf("configure rate limiter: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	pool, err := database.Open(connectCtx, cfg.DatabaseURL)
	cancel()
	if err != nil {
		return err
	}
	defer pool.Close()

	repository := postgres.NewThreatRepository(pool)
	threatService := service.NewThreatService(repository)
	handler := httptransport.NewRouter(threatService, logger, limiter)
	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		limiter.Run(ctx)
	}()
	defer func() {
		stop()
		<-cleanupDone
	}()

	server := httptransport.NewServer(cfg.HTTPAddr, handler, tlsConfig)
	serveErrors := make(chan error, 1)
	go func() {
		logger.Printf("Listening for HTTPS on %s", cfg.HTTPAddr)
		serveErrors <- server.ListenAndServeTLS("", "")
	}()
	select {
	case err := <-serveErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve HTTPS: %w", err)
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return fmt.Errorf("shutdown HTTPS server: %w", err)
		}
	}
	return nil
}
