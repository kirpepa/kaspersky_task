package httptransport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadServerTLS(t *testing.T) {
	now := time.Now()
	certFile, keyFile := writeTLSFixture(t, now.Add(-time.Hour), now.Add(time.Hour))
	cfg, err := LoadServerTLS(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("minimum TLS version = %x, want TLS 1.2", cfg.MinVersion)
	}
	if len(cfg.Certificates) != 1 || cfg.Certificates[0].Leaf == nil {
		t.Fatal("server certificate was not loaded")
	}
}

func TestLoadServerTLSRejectsInvalidFiles(t *testing.T) {
	now := time.Now()
	certFile, keyFile := writeTLSFixture(t, now.Add(-time.Hour), now.Add(time.Hour))
	_, unrelatedKey := writeTLSFixture(t, now.Add(-time.Hour), now.Add(time.Hour))
	invalidFile := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(invalidFile, []byte("invalid PEM"), 0600); err != nil {
		t.Fatal(err)
	}
	missingFile := filepath.Join(t.TempDir(), "missing.pem")
	for _, tt := range []struct {
		name, cert, key string
	}{
		{"missing certificate", missingFile, keyFile},
		{"missing key", certFile, missingFile},
		{"invalid certificate", invalidFile, keyFile},
		{"invalid key", certFile, invalidFile},
		{"mismatched pair", certFile, unrelatedKey},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadServerTLS(tt.cert, tt.key)
			if err == nil || cfg != nil {
				t.Fatalf("invalid certificate/key accepted: config=%v error=%v", cfg, err)
			}
		})
	}
}

func TestLoadServerTLSRejectsInvalidValidity(t *testing.T) {
	now := time.Now()
	for _, tt := range []struct {
		name                string
		notBefore, notAfter time.Time
		message             string
	}{
		{"expired", now.Add(-2 * time.Hour), now.Add(-time.Hour), "expired"},
		{"future", now.Add(time.Hour), now.Add(2 * time.Hour), "not valid before"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			certFile, keyFile := writeTLSFixture(t, tt.notBefore, tt.notAfter)
			cfg, err := LoadServerTLS(certFile, keyFile)
			if err == nil || cfg != nil {
				t.Fatalf("invalid certificate validity accepted: config=%v error=%v", cfg, err)
			}
			if !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("error = %q, want %q", err, tt.message)
			}
		})
	}
}

func writeTLSFixture(t *testing.T, notBefore, notAfter time.Time) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	for path, block := range map[string]*pem.Block{
		certFile: {Type: "CERTIFICATE", Bytes: der},
		keyFile:  {Type: "PRIVATE KEY", Bytes: keyDER},
	} {
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return certFile, keyFile
}
