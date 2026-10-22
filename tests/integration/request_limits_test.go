package integration_test

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"kasper/internal/repository/memory"
	"kasper/internal/service"
	httptransport "kasper/internal/transport/http"
)

func TestChunkedRequestSizeBoundaries(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		for _, offset := range []int{-1, 0, 1} {
			t.Run(fmt.Sprintf("%s/limit%+d", method, offset), func(t *testing.T) {
				router := httptransport.NewRouter(service.NewThreatService(memory.NewThreatRepository()), log.New(io.Discard, "", 0), nil)
				var chunked atomic.Bool
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == method && len(r.TransferEncoding) == 1 && r.TransferEncoding[0] == "chunked" && r.ContentLength == -1 {
						chunked.Store(true)
					}
					router.ServeHTTP(w, r)
				}))
				t.Cleanup(server.Close)
				server.Client().Timeout = 5 * time.Second
				path := "/info"
				prefix := `{"md5":"` + md5 + `","name":"test","ignored":"`
				if method == http.MethodPut {
					request(t, server, http.MethodPost, "/info", `{"md5":"`+md5+`","name":"original"}`, 201)
					path += "/" + md5
					prefix = `{"name":"test","ignored":"`
				}
				size := int(httptransport.MaxRequestBodyBytes) + offset
				body := prefix + strings.Repeat("x", size-len(prefix)-2) + `"}`
				// Wrapping the reader prevents net/http from inferring a length.
				req, err := http.NewRequest(method, server.URL+path, io.NopCloser(strings.NewReader(body)))
				if err != nil {
					t.Fatal(err)
				}
				req.ContentLength = -1
				req.Header.Set("Content-Type", "application/json")
				response, err := server.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				data, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				if !chunked.Load() {
					t.Fatal("request did not arrive with chunked transfer encoding")
				}
				wantStatus := http.StatusOK
				if method == http.MethodPost {
					wantStatus = http.StatusCreated
				}
				if offset > 0 {
					wantStatus = http.StatusRequestEntityTooLarge
				}
				if response.StatusCode != wantStatus {
					t.Fatalf("status = %d, want %d; body = %s", response.StatusCode, wantStatus, data)
				}
				assertOpenAPIResponse(t, req, response.StatusCode, response.Header, data)
				if offset > 0 {
					if !response.Close {
						t.Error("oversized request connection was kept alive")
					}
					if method == http.MethodPost {
						request(t, server, http.MethodGet, "/info/"+md5, "", 404)
					} else {
						assertThreat(t, request(t, server, http.MethodGet, "/info/"+md5, "", 200), threat{MD5: md5, Name: "original", Severity: "unknown"})
					}
				} else {
					assertThreat(t, data, threat{MD5: md5, Name: "test", Severity: "unknown"})
				}
			})
		}
	}
}

func TestOversizedContentLengthIsRejectedBeforeClientSendsBody(t *testing.T) {
	server := newServerWithRepository(t, memory.NewThreatRepository())
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			path := "/info"
			if method == http.MethodPut {
				path += "/" + md5
			}
			connection, err := net.DialTimeout("tcp", server.Listener.Addr().String(), 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			_, err = fmt.Fprintf(connection, "%s %s HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", method, path, httptransport.MaxRequestBodyBytes+1)
			if err != nil {
				t.Fatal(err)
			}
			assertWireRequestError(t, connection, method, path, 413)
		})
	}
}

func assertWireRequestError(t *testing.T, connection net.Conn, method, path string, status int) {
	t.Helper()
	req, err := http.NewRequest(method, "http://localhost"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), req)
	if err != nil {
		t.Fatalf("server did not promptly return an error: %v", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != status {
		t.Fatalf("status = %d, want %d; body = %s", response.StatusCode, status, data)
	}
	if !response.Close {
		t.Error("incomplete request connection was kept alive")
	}
	assertOpenAPIResponse(t, req, response.StatusCode, response.Header, data)
}
