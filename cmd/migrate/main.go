package main

import (
	"context"
	"log"
	"time"

	"kasper/internal/config"
	"kasper/internal/database"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
	log.Print("Database migrations applied")
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	return database.ApplyMigrations(ctx, pool)
}
