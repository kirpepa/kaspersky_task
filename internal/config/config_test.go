package config_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"kasper/internal/config"
)

func TestDatabaseURLIsRequired(t *testing.T) {
	for _, value := range []string{"", " \t\n"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("DATABASE_URL", value)
			if _, err := config.Load(); err == nil || !strings.Contains(err.Error(), "DATABASE_URL") {
				t.Fatalf("Load error = %v; want a missing DATABASE_URL error", err)
			}
		})
	}
}

func TestLoadAddressesFromEnvironment(t *testing.T) {
	const databaseURL = "postgres://user:password@localhost:5432/threats?sslmode=disable"
	t.Setenv("DATABASE_URL", databaseURL)
	for _, address := range []string{"", "127.0.0.1:9090"} {
		t.Run(address, func(t *testing.T) {
			t.Setenv("HTTP_ADDR", address)
			cfg, err := config.Load()
			if err != nil {
				t.Fatal(err)
			}
			want := address
			if want == "" {
				want = ":8443"
			}
			if cfg.HTTPAddr != want || cfg.DatabaseURL != databaseURL {
				t.Fatal("Load did not preserve the configured database URL and HTTP address")
			}
		})
	}
}

func TestLoadTLSDefaults(t *testing.T) {
	clearTLSEnvironment(t)
	t.Setenv("DATABASE_URL", "")
	got, err := config.LoadTLS()
	if err != nil {
		t.Fatal(err)
	}
	want := config.TLSConfig{CertFile: "certs/server.crt", KeyFile: "certs/server.key"}
	if got != want {
		t.Fatalf("LoadTLS() = %+v; want %+v", got, want)
	}
}

func TestLoadTLSOverrides(t *testing.T) {
	clearTLSEnvironment(t)
	const certFile = "/tmp/server certificates/custom.crt"
	const keyFile = "/tmp/server certificates/custom.key"
	for _, test := range []struct {
		name        string
		environment map[string]string
		want        config.TLSConfig
	}{
		{
			name:        "certificate and key",
			environment: map[string]string{"TLS_CERT_FILE": certFile, "TLS_KEY_FILE": keyFile},
			want:        config.TLSConfig{CertFile: certFile, KeyFile: keyFile},
		},
		{
			name:        "certificate with default key",
			environment: map[string]string{"TLS_CERT_FILE": certFile},
			want:        config.TLSConfig{CertFile: certFile, KeyFile: "certs/server.key"},
		},
		{
			name:        "key with default certificate",
			environment: map[string]string{"TLS_KEY_FILE": keyFile},
			want:        config.TLSConfig{CertFile: "certs/server.crt", KeyFile: keyFile},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			for name, value := range test.environment {
				t.Setenv(name, value)
			}
			got, err := config.LoadTLS()
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("LoadTLS() = %+v; want %+v", got, test.want)
			}
		})
	}
}

func TestLoadTLSRejectsEmptyPaths(t *testing.T) {
	clearTLSEnvironment(t)
	for _, name := range []string{"TLS_CERT_FILE", "TLS_KEY_FILE"} {
		for _, value := range []string{"", " \t\n"} {
			t.Run(name+"/"+value, func(t *testing.T) {
				t.Setenv(name, value)
				if _, err := config.LoadTLS(); err == nil || !strings.Contains(err.Error(), name) {
					t.Fatalf("LoadTLS error = %v; want an error naming %s", err, name)
				}
			})
		}
	}
}

func TestLoadDoesNotDependOnTLSSettings(t *testing.T) {
	t.Setenv("DATABASE_URL", "host=localhost dbname=threats")
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", " \t\n")
	if _, err := config.Load(); err != nil {
		t.Fatalf("database and migration configuration must ignore HTTPS certificate paths: %v", err)
	}
}

func clearTLSEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{"TLS_CERT_FILE", "TLS_KEY_FILE"} {
		// Setenv registers restoration of the original environment for this test.
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoadRateLimitDefaults(t *testing.T) {
	clearRateLimitEnvironment(t)
	t.Setenv("DATABASE_URL", "")
	got, err := config.LoadRateLimit()
	if err != nil {
		t.Fatal(err)
	}
	want := config.RateLimitConfig{RPS: 10, Burst: 20, MaxClients: 10000, IdleTTL: 10 * time.Minute}
	if got != want {
		t.Fatalf("LoadRateLimit() = %+v; want %+v", got, want)
	}
}

func TestLoadRateLimitOverrides(t *testing.T) {
	clearRateLimitEnvironment(t)
	t.Setenv("RATE_LIMIT_RPS", "0.5")
	t.Setenv("RATE_LIMIT_BURST", "3")
	t.Setenv("RATE_LIMIT_MAX_CLIENTS", "123")
	t.Setenv("RATE_LIMIT_IDLE_TTL", "1m30s")
	got, err := config.LoadRateLimit()
	if err != nil {
		t.Fatal(err)
	}
	want := config.RateLimitConfig{RPS: 0.5, Burst: 3, MaxClients: 123, IdleTTL: 90 * time.Second}
	if got != want {
		t.Fatalf("LoadRateLimit() = %+v; want %+v", got, want)
	}
}

func TestLoadRateLimitRejectsInvalidSettings(t *testing.T) {
	clearRateLimitEnvironment(t)
	for _, setting := range []struct {
		name   string
		values []string
	}{
		{"RATE_LIMIT_RPS", []string{"", " ", "invalid", "0", "-1", "NaN", "Inf", "+Inf", "-Inf", "1e309"}},
		{"RATE_LIMIT_BURST", []string{"", " ", "invalid", "0", "-1", "1.5", "999999999999999999999"}},
		{"RATE_LIMIT_MAX_CLIENTS", []string{"", " ", "invalid", "0", "-1", "1.5", "999999999999999999999"}},
		{"RATE_LIMIT_IDLE_TTL", []string{"", " ", "invalid", "0s", "-1s", "10", "999999999999h"}},
	} {
		for _, value := range setting.values {
			t.Run(setting.name+"/"+value, func(t *testing.T) {
				t.Setenv(setting.name, value)
				if _, err := config.LoadRateLimit(); err == nil || !strings.Contains(err.Error(), setting.name) {
					t.Fatalf("LoadRateLimit error = %v; want an error naming %s", err, setting.name)
				}
			})
		}
	}
}

func TestLoadDoesNotDependOnRateLimitSettings(t *testing.T) {
	t.Setenv("DATABASE_URL", "host=localhost dbname=threats")
	for _, name := range rateLimitVariables {
		t.Setenv(name, "invalid")
	}
	if _, err := config.Load(); err != nil {
		t.Fatalf("database and migration configuration must ignore HTTP rate limits: %v", err)
	}
}

var rateLimitVariables = []string{
	"RATE_LIMIT_RPS", "RATE_LIMIT_BURST", "RATE_LIMIT_MAX_CLIENTS", "RATE_LIMIT_IDLE_TTL",
}

func clearRateLimitEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range rateLimitVariables {
		// Setenv registers restoration of the original environment for this test.
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
}
