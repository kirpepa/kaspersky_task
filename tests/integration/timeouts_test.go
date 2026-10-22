package integration_test

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"testing"
	"time"

	"kasper/internal/repository/memory"
	"kasper/internal/service"
	httptransport "kasper/internal/transport/http"
)

func TestHTTPServerClosesIncompleteHeaders(t *testing.T) {
	connection, observed := newTimeoutConnection(t)
	if _, err := io.WriteString(connection, "POST /info HTTP/1.1\r\nHost: localhost\r\nX-Incomplete:"); err != nil {
		t.Fatal(err)
	}
	assertTimeoutConnectionClosed(t, connection)
	if observed.calls.Load() != 0 {
		t.Fatal("incomplete headers reached the service")
	}
}

func TestHTTPServerRejectsIncompleteBody(t *testing.T) {
	connection, observed := newTimeoutConnection(t)
	if _, err := io.WriteString(connection, "POST /info HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"name\":"); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "https://localhost/info", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), request)
	if err != nil {
		t.Fatalf("read timed-out request response: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("incomplete body response = %d %s, want 408", response.StatusCode, body)
	}
	assertOpenAPIResponse(t, request, response.StatusCode, response.Header, body)
	if observed.calls.Load() != 0 {
		t.Fatal("incomplete body reached the service")
	}
}

func TestHTTPServerClosesIdleKeepAliveConnection(t *testing.T) {
	connection, observed := newTimeoutConnection(t)
	if _, err := fmt.Fprintf(connection, "GET /info/%s HTTP/1.1\r\nHost: localhost\r\n\r\n", md5); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound || response.Close {
		t.Fatalf("initial response = %d, close = %v; want reusable 404", response.StatusCode, response.Close)
	}
	assertTimeoutConnectionClosed(t, connection)
	if observed.calls.Load() != 1 {
		t.Fatalf("service calls = %d, want 1", observed.calls.Load())
	}
}

func TestHTTPServerCannotWriteResponseAfterDeadline(t *testing.T) {
	written := make(chan error, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-time.After(500 * time.Millisecond)
		_, err := io.WriteString(w, "late response")
		if err == nil {
			err = http.NewResponseController(w).Flush()
		}
		written <- err
	})
	connection := openTimeoutConnection(t, handler, func(server *http.Server) {
		server.WriteTimeout = 250 * time.Millisecond
	})
	if _, err := io.WriteString(connection, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if response != nil {
		response.Body.Close()
	}
	if err == nil {
		t.Fatal("client received a successful response after the write deadline")
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		t.Fatalf("connection survived until the client deadline: %v", err)
	}
	select {
	case err := <-written:
		if !errors.As(err, &networkError) || !networkError.Timeout() {
			t.Fatalf("server write error = %v, want a timeout", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish writing")
	}
}

func newTimeoutConnection(t *testing.T) (*tls.Conn, *tlsObservedService) {
	t.Helper()
	observed := &tlsObservedService{delegate: service.NewThreatService(memory.NewThreatRepository())}
	handler := httptransport.NewRouter(observed, log.New(io.Discard, "", 0), nil)
	return openTimeoutConnection(t, handler, nil), observed
}

func openTimeoutConnection(t *testing.T, handler http.Handler, configure func(*http.Server)) *tls.Conn {
	t.Helper()
	certFile, keyFile, roots := createTLSCertificate(t)
	tlsConfig, err := httptransport.LoadServerTLS(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	logger := log.New(io.Discard, "", 0)
	server := httptransport.NewServer("", handler, tlsConfig)
	// Production defaults are asserted separately. Shorter intervals keep these
	// actual socket checks fast; client deadlines allow slow test environments.
	server.ReadHeaderTimeout = 250 * time.Millisecond
	server.ReadTimeout = 500 * time.Millisecond
	server.WriteTimeout = 5 * time.Second
	server.IdleTimeout = 250 * time.Millisecond
	server.ErrorLog = logger
	if configure != nil {
		configure(server)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- server.ServeTLS(listener, "", "") }()
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("close timeout test server: %v", err)
		}
		select {
		case err := <-finished:
			if !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("timeout test server exited: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("timeout test server did not stop")
		}
	})
	connection, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", listener.Addr().String(), &tls.Config{
		RootCAs: roots, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close() })
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return connection
}

func assertTimeoutConnectionClosed(t *testing.T, connection net.Conn) {
	t.Helper()
	var buffer [1]byte
	n, err := connection.Read(buffer[:])
	if n != 0 || err == nil {
		t.Fatalf("connection remained usable: read %d bytes, error %v", n, err)
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		t.Fatalf("server did not close connection before the client deadline: %v", err)
	}
}
