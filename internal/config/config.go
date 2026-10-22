package config

import (
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr    string
	DatabaseURL string
}

// TLSConfig identifies the certificate and private key used by the HTTPS server.
type TLSConfig struct {
	CertFile string
	KeyFile  string
}

// RateLimitConfig controls the HTTP request limit for each client IP.
type RateLimitConfig struct {
	RPS        float64
	Burst      int
	MaxClients int
	IdleTTL    time.Duration
}

func Load() (Config, error) {
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8443"
	}
	databaseURL := os.Getenv("DATABASE_URL")
	if strings.TrimSpace(databaseURL) == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}
	return Config{HTTPAddr: addr, DatabaseURL: databaseURL}, nil
}

// LoadTLS loads certificate paths separately from the migration configuration.
// The HTTPS server checks the files when it loads the certificate and key.
func LoadTLS() (TLSConfig, error) {
	cfg := TLSConfig{CertFile: "certs/server.crt", KeyFile: "certs/server.key"}
	for _, setting := range []struct {
		name   string
		target *string
	}{
		{"TLS_CERT_FILE", &cfg.CertFile},
		{"TLS_KEY_FILE", &cfg.KeyFile},
	} {
		if value, present := os.LookupEnv(setting.name); present {
			if strings.TrimSpace(value) == "" {
				return TLSConfig{}, fmt.Errorf("%s must not be empty", setting.name)
			}
			*setting.target = value
		}
	}
	return cfg, nil
}

// LoadRateLimit loads HTTP-only settings separately from the migration configuration.
// Explicitly empty values are invalid; defaults apply only to missing variables.
func LoadRateLimit() (RateLimitConfig, error) {
	cfg := RateLimitConfig{
		RPS:        10,
		Burst:      20,
		MaxClients: 10000,
		IdleTTL:    10 * time.Minute,
	}
	var err error
	if value, present := os.LookupEnv("RATE_LIMIT_RPS"); present {
		cfg.RPS, err = strconv.ParseFloat(value, 64)
		if err != nil || math.IsNaN(cfg.RPS) || math.IsInf(cfg.RPS, 0) || cfg.RPS <= 0 {
			return RateLimitConfig{}, errors.New("RATE_LIMIT_RPS must be a positive finite number")
		}
	}
	for _, setting := range []struct {
		name   string
		target *int
	}{
		{"RATE_LIMIT_BURST", &cfg.Burst},
		{"RATE_LIMIT_MAX_CLIENTS", &cfg.MaxClients},
	} {
		if value, present := os.LookupEnv(setting.name); present {
			*setting.target, err = strconv.Atoi(value)
			if err != nil || *setting.target <= 0 {
				return RateLimitConfig{}, fmt.Errorf("%s must be a positive integer", setting.name)
			}
		}
	}
	if value, present := os.LookupEnv("RATE_LIMIT_IDLE_TTL"); present {
		cfg.IdleTTL, err = time.ParseDuration(value)
		if err != nil || cfg.IdleTTL <= 0 {
			return RateLimitConfig{}, errors.New("RATE_LIMIT_IDLE_TTL must be a positive duration, for example 10m")
		}
	}
	return cfg, nil
}
