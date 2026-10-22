package integration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"kasper/internal/domain"
	"kasper/internal/repository/memory"
	"kasper/internal/service"
	httptransport "kasper/internal/transport/http"
)

func TestTLSClientCanCreateReadUpdateAndIsRateLimited(t *testing.T) {
	server := newTLSServer(t, 3)
	_, body := tlsAPIRequest(t, server, "POST", "/info", `{"md5":"`+md5+`","name":"original"}`, 201)
	want := threat{MD5: md5, Name: "original", Severity: "unknown"}
	assertThreat(t, body, want)
	_, body = tlsAPIRequest(t, server, "GET", "/info/"+md5, "", 200)
	assertThreat(t, body, want)
	_, body = tlsAPIRequest(t, server, "PUT", "/info/"+md5, `{"name":"updated","description":"over TLS","severity":"high"}`, 200)
	want.Name, want.Description, want.Severity = "updated", "over TLS", "high"
	assertThreat(t, body, want)

	response, body := tlsAPIRequest(t, server, "GET", "/info/"+md5, "", 429)
	retry, err := strconv.Atoi(response.Header.Get("Retry-After"))
	if err != nil || retry < 1 {
		t.Errorf("Retry-After = %q, want positive integer", response.Header.Get("Retry-After"))
	}
	var failure struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &failure); err != nil || failure.Message == "" {
		t.Errorf("invalid 429 response: %s (decode error: %v)", body, err)
	}
	if calls := server.service.calls.Load(); calls != 3 {
		t.Errorf("service calls = %d, want 3", calls)
	}
}

func TestTLSClientRejectsUntrustedCAAndWrongHostname(t *testing.T) {
	for _, test := range []struct {
		name, serverName string
		untrustedCA      bool
	}{
		{"untrusted CA", "", true},
		{"wrong hostname", "wrong.example", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := newTLSServer(t, 1)
			config := &tls.Config{RootCAs: server.roots, ServerName: test.serverName, MinVersion: tls.VersionTLS12}
			if test.untrustedCA {
				config.RootCAs = x509.NewCertPool()
			}
			response, err := newTLSClient(t, config).Get(server.url + "/info/" + md5)
			if response != nil {
				response.Body.Close()
			}
			if err == nil {
				t.Fatal("TLS connection unexpectedly accepted the certificate")
			}
			if test.untrustedCA {
				var expected x509.UnknownAuthorityError
				if !errors.As(err, &expected) {
					t.Errorf("error = %v, want x509.UnknownAuthorityError", err)
				}
			} else {
				var expected x509.HostnameError
				if !errors.As(err, &expected) {
					t.Errorf("error = %v, want x509.HostnameError", err)
				}
			}
			if server.service.calls.Load() != 0 {
				t.Fatal("failed TLS verification reached the service")
			}
		})
	}
}

func TestPlainHTTPDoesNotReachTLSService(t *testing.T) {
	server := newTLSServer(t, 1)
	plainURL := "http://" + strings.TrimPrefix(server.url, "https://") + "/info"
	response, err := server.client.Post(plainURL, "application/json", strings.NewReader(`{"md5":"`+md5+`","name":"test"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Errorf("HTTP on TLS port returned %d, want 400", response.StatusCode)
	}
	if server.service.calls.Load() != 0 {
		t.Fatal("unencrypted HTTP request reached the service")
	}
}

func TestTLS11DoesNotReachService(t *testing.T) {
	server := newTLSServer(t, 1)
	client := newTLSClient(t, &tls.Config{
		RootCAs:    server.roots,
		MinVersion: tls.VersionTLS11,
		MaxVersion: tls.VersionTLS11,
	})
	response, err := client.Get(server.url + "/info/" + md5)
	if response != nil {
		response.Body.Close()
	}
	if err == nil {
		t.Fatal("server unexpectedly accepted TLS 1.1")
	}
	if server.service.calls.Load() != 0 {
		t.Fatal("TLS 1.1 request reached the service")
	}
}

type tlsTestServer struct {
	url     string
	client  *http.Client
	roots   *x509.CertPool
	service *tlsObservedService
}

func newTLSServer(t *testing.T, burst int) *tlsTestServer {
	t.Helper()
	certFile, keyFile, roots := createTLSCertificate(t)
	config, err := httptransport.LoadServerTLS(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	limiter, err := httptransport.NewIPRateLimiter(1e-6, burst, 32, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	observed := &tlsObservedService{delegate: service.NewThreatService(memory.NewThreatRepository())}
	logger := log.New(io.Discard, "", 0)
	server := &http.Server{
		Handler:   httptransport.NewRouter(observed, logger, limiter),
		TLSConfig: config,
		ErrorLog:  logger,
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- server.ServeTLS(listener, "", "") }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			server.Close()
			t.Errorf("shutdown TLS test server: %v", err)
		}
		select {
		case err := <-finished:
			if !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("TLS test server exited: %v", err)
			}
		case <-ctx.Done():
			t.Error("TLS test server did not stop")
		}
	})
	return &tlsTestServer{
		url:     "https://" + listener.Addr().String(),
		client:  newTLSClient(t, &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}),
		roots:   roots,
		service: observed,
	}
}

func newTLSClient(t *testing.T, config *tls.Config) *http.Client {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: config}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func tlsAPIRequest(t *testing.T, server *tlsTestServer, method, path, body string, status int) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequest(method, server.url+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := server.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != status {
		t.Fatalf("%s %s: status = %d, want %d; body = %s", method, path, response.StatusCode, status, data)
	}
	if response.TLS == nil || response.TLS.Version < tls.VersionTLS12 {
		t.Fatal("response was not delivered over TLS 1.2 or newer")
	}
	assertOpenAPIResponse(t, request, response.StatusCode, response.Header, data)
	return response, data
}

func createTLSCertificate(t *testing.T) (string, string, *x509.CertPool) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Kasper integration test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, leaf, rootCert, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, roots
}

type tlsObservedService struct {
	delegate *service.ThreatService
	calls    atomic.Int32
}

func (s *tlsObservedService) Create(ctx context.Context, input service.CreateThreatInput) (domain.Threat, error) {
	s.calls.Add(1)
	return s.delegate.Create(ctx, input)
}

func (s *tlsObservedService) GetByMD5(ctx context.Context, md5 string) (domain.Threat, error) {
	s.calls.Add(1)
	return s.delegate.GetByMD5(ctx, md5)
}

func (s *tlsObservedService) Update(ctx context.Context, md5 string, input service.UpdateThreatInput) (domain.Threat, error) {
	s.calls.Add(1)
	return s.delegate.Update(ctx, md5, input)
}
