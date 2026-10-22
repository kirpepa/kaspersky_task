package integration_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"kasper/internal/repository/memory"
	"kasper/internal/service"
	httptransport "kasper/internal/transport/http"
)

func TestRateLimitRejectsIncompleteHTTP1BodiesPromptly(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		for _, framing := range []struct{ name, header string }{
			{"content length", "Content-Length: 10"},
			{"chunked", "Transfer-Encoding: chunked"},
		} {
			t.Run(method+"/"+framing.name, func(t *testing.T) {
				limiter, err := httptransport.NewIPRateLimiter(1e-6, 1, 32, 365*24*time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				router := httptransport.NewRouter(service.NewThreatService(memory.NewThreatRepository()), log.New(io.Discard, "", 0), limiter)
				connection := openTimeoutConnection(t, router, func(server *http.Server) {
					server.ReadTimeout = 5 * time.Second
				})
				// Consume the only token using the same reusable TLS connection.
				if _, err := fmt.Fprintf(connection, "GET /info/%s HTTP/1.1\r\nHost: localhost\r\n\r\n", md5); err != nil {
					t.Fatal(err)
				}
				initial, err := http.ReadResponse(bufio.NewReader(connection), nil)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.Copy(io.Discard, initial.Body); err != nil {
					t.Fatal(err)
				}
				initial.Body.Close()
				if initial.StatusCode != http.StatusNotFound || initial.Close {
					t.Fatalf("initial response = %d, close = %v; want reusable 404", initial.StatusCode, initial.Close)
				}
				// The response must arrive without sending a body or waiting for
				// the server's longer read deadline to abort net/http's drain.
				if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
					t.Fatal(err)
				}
				path := "/info"
				if method == http.MethodPut {
					path += "/" + md5
				}
				if _, err := fmt.Fprintf(connection, "%s %s HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n%s\r\n\r\n", method, path, framing.header); err != nil {
					t.Fatal(err)
				}
				assertWireRequestError(t, connection, method, path, http.StatusTooManyRequests)
			})
		}
	}
}

func TestRateLimitConcurrentHTTPConnectionsCannotExceedBurst(t *testing.T) {
	const burst, total = 8, 40
	limiter, err := httptransport.NewIPRateLimiter(1e-6, burst, 32, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	repository := memory.NewThreatRepository()
	server := httptest.NewServer(httptransport.NewRouter(service.NewThreatService(repository), log.New(io.Discard, "", 0), limiter))
	t.Cleanup(server.Close)
	transport := &http.Transport{DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	request(t, server, "POST", "/info", `{"md5":"`+md5+`","name":"original"}`, 201)

	type result struct {
		response *http.Response
		body     []byte
		err      error
	}
	results := make(chan result, total)
	start := make(chan struct{})
	for range total {
		go func() {
			<-start
			response, err := client.Get(server.URL + "/info/" + md5)
			if err != nil {
				results <- result{err: err}
				return
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			results <- result{response: response, body: body, err: err}
		}()
	}
	close(start)
	allowed, rejected := 0, 0
	for range total {
		result := <-results
		if result.err != nil {
			t.Errorf("concurrent HTTP request: %v", result.err)
			continue
		}
		response := result.response
		assertOpenAPIResponse(t, response.Request, response.StatusCode, response.Header, result.body)
		switch response.StatusCode {
		case http.StatusOK:
			allowed++
			assertThreat(t, result.body, threat{MD5: md5, Name: "original", Severity: "unknown"})
		case http.StatusTooManyRequests:
			rejected++
			retry, err := strconv.Atoi(response.Header.Get("Retry-After"))
			if err != nil || retry < 1 {
				t.Errorf("Retry-After = %q, want positive integer", response.Header.Get("Retry-After"))
			}
			var body struct {
				Message string `json:"message"`
			}
			if err := json.Unmarshal(result.body, &body); err != nil || body.Message == "" {
				t.Errorf("invalid 429 response: %s (decode error: %v)", result.body, err)
			}
		default:
			t.Errorf("unexpected status = %d; body = %s", response.StatusCode, result.body)
		}
	}
	// The initial POST uses one token; all connections share the same client IP.
	if allowed != burst-1 || rejected != total-(burst-1) {
		t.Errorf("allowed = %d, rejected = %d; want %d and %d", allowed, rejected, burst-1, total-(burst-1))
	}
}
