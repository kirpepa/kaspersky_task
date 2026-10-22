package httptransport_test

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"kasper/internal/domain"
	httptransport "kasper/internal/transport/http"
)

func TestRateLimitUsesCanonicalClientIP(t *testing.T) {
	tests := []struct {
		name      string
		addresses []string
		statuses  []int
	}{
		{"independent IPv4 addresses", []string{"192.0.2.1:1000", "192.0.2.2:1000", "192.0.2.1:2000", "192.0.2.2:2000"}, []int{200, 200, 429, 429}},
		{"same IP different ports", []string{"192.0.2.1:1000", "192.0.2.1:2000"}, []int{200, 429}},
		{"IPv4 then mapped IPv6", []string{"192.0.2.1:1000", "[::ffff:192.0.2.1]:2000"}, []int{200, 429}},
		{"mapped IPv6 then IPv4", []string{"[::ffff:192.0.2.1]:1000", "192.0.2.1:2000"}, []int{200, 429}},
		{"equivalent IPv6", []string{"[2001:db8::1]:1000", "[2001:0db8:0000:0000:0000:0000:0000:0001]:2000"}, []int{200, 429}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router, calls := newRateLimitedRouter(t, 1)
			var allowed int32
			for i, address := range tt.addresses {
				request := httptest.NewRequest("GET", "/info/"+testMD5, nil)
				request.RemoteAddr = address
				response := httptest.NewRecorder()
				router.ServeHTTP(response, request)
				if tt.statuses[i] == 429 {
					assertRateLimitError(t, request, response, 429)
					continue
				}
				allowed++
				if response.Code != 200 {
					t.Fatalf("%s: status = %d, want 200; body = %s", address, response.Code, response.Body.String())
				}
			}
			if got := calls.Load(); got != allowed {
				t.Errorf("service calls = %d, want %d", got, allowed)
			}
		})
	}
}

func TestRateLimitIgnoresUntrustedProxyHeaders(t *testing.T) {
	tests := []struct{ header, first, changed string }{
		{"X-Forwarded-For", "203.0.113.1", "203.0.113.2, 203.0.113.3"},
		{"X-Real-IP", "203.0.113.1", "203.0.113.2"},
		{"Forwarded", "for=203.0.113.1;proto=https", "for=203.0.113.2;proto=https"},
	}
	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			router, calls := newRateLimitedRouter(t, 1)
			requests := []struct {
				address, value string
				status         int
			}{
				{"192.0.2.1:1000", tt.first, 200},
				{"192.0.2.1:2000", tt.changed, 429},
				{"192.0.2.2:1000", tt.first, 200},
			}
			for _, item := range requests {
				request := httptest.NewRequest("GET", "/info/"+testMD5, nil)
				request.RemoteAddr = item.address
				request.Header.Set(tt.header, item.value)
				response := httptest.NewRecorder()
				router.ServeHTTP(response, request)
				if item.status == 429 {
					assertRateLimitError(t, request, response, 429)
				} else if response.Code != item.status {
					t.Errorf("%s=%q from %s: status = %d, want %d", tt.header, item.value, item.address, response.Code, item.status)
				}
			}
			if got := calls.Load(); got != 2 {
				t.Errorf("service calls = %d, want 2", got)
			}
		})
	}
}

func TestRateLimitSharesBudgetAcrossAPIOperations(t *testing.T) {
	router, calls := newRateLimitedRouter(t, 3)
	operations := []struct {
		method, path, body string
		status             int
	}{
		{"POST", "/info", `{"md5":"` + testMD5 + `","name":"test"}`, 201},
		{"GET", "/info/" + testMD5, "", 200},
		{"PUT", "/info/" + testMD5, `{"name":"test"}`, 200},
	}
	for round := range 2 {
		for _, operation := range operations {
			request := httptest.NewRequest(operation.method, operation.path, strings.NewReader(operation.body))
			request.RemoteAddr = "192.0.2.1:1000"
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if round == 1 {
				assertRateLimitError(t, request, response, 429)
				continue
			}
			if response.Code != operation.status {
				t.Fatalf("%s: status = %d, want %d; body = %s", operation.method, response.Code, operation.status, response.Body.String())
			}
			assertOpenAPIResponse(t, request, response)
		}
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("service calls = %d, want 3", got)
	}
}

func TestRateLimitRejectsBeforeReadingBodyOrCallingService(t *testing.T) {
	for _, protocol := range []int{1, 2} {
		t.Run("HTTP/"+strconv.Itoa(protocol), func(t *testing.T) {
			router, calls := newRateLimitedRouter(t, 1)
			request := httptest.NewRequest("GET", "/info/"+testMD5, nil)
			request.RemoteAddr = "192.0.2.1:1000"
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != 200 {
				t.Fatalf("initial request: status = %d, body = %s", response.Code, response.Body.String())
			}

			body := &bodyReadProbe{}
			request = httptest.NewRequest("POST", "/info", body)
			request.ProtoMajor = protocol
			request.RemoteAddr = "192.0.2.1:2000"
			request.Header.Set("Content-Type", "application/json")
			response = httptest.NewRecorder()
			router.ServeHTTP(response, request)
			assertRateLimitError(t, request, response, 429)
			if body.reads != 0 {
				t.Errorf("rate-limited body read %d times, want 0", body.reads)
			}
			if got := calls.Load(); got != 1 {
				t.Errorf("service calls = %d, want only the initial call", got)
			}
			wantConnection := ""
			if protocol == 1 {
				wantConnection = "close"
			}
			if got := response.Header().Get("Connection"); got != wantConnection {
				t.Errorf("Connection = %q, want %q", got, wantConnection)
			}
		})
	}
}

func TestRateLimitPreservesUnknownRoutesAndUnsupportedMethods(t *testing.T) {
	router, calls := newRateLimitedRouter(t, 1)
	initial := httptest.NewRequest("GET", "/info/"+testMD5, nil)
	initial.RemoteAddr = "192.0.2.1:1000"
	response := httptest.NewRecorder()
	router.ServeHTTP(response, initial)
	if response.Code != 200 {
		t.Fatalf("initial request status = %d, want 200", response.Code)
	}
	for _, tt := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/missing", 404},
		{"GET", "/info", 405},
		{"DELETE", "/info/" + testMD5, 405},
		{"POST", "/info/" + testMD5, 405},
	} {
		request := httptest.NewRequest(tt.method, tt.path, nil)
		request.RemoteAddr = initial.RemoteAddr
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != tt.status {
			t.Errorf("%s %s: status = %d, want %d", tt.method, tt.path, response.Code, tt.status)
		}
		if response.Header().Get("Retry-After") != "" {
			t.Errorf("%s %s unexpectedly rate limited", tt.method, tt.path)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("unmatched routes called service: calls = %d, want 1", got)
	}
}

func TestRateLimitRejectsInvalidRemoteAddress(t *testing.T) {
	for _, address := range []string{"", "garbage", "localhost:1234", "192.0.2.1:not-a-port", "[::1]"} {
		t.Run(address, func(t *testing.T) {
			router, calls := newRateLimitedRouter(t, 1)
			request := httptest.NewRequest("GET", "/info/"+testMD5, nil)
			request.RemoteAddr = address
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			assertRateLimitError(t, request, response, 400)
			if calls.Load() != 0 {
				t.Fatal("invalid remote address reached service")
			}
		})
	}
}

func newRateLimitedRouter(t *testing.T, burst int) (http.Handler, *atomic.Int32) {
	t.Helper()
	limiter, err := httptransport.NewIPRateLimiter(1e-6, burst, 32, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	calls := &atomic.Int32{}
	service := fakeService{call: func() (domain.Threat, error) {
		calls.Add(1)
		return domain.Threat{MD5: testMD5, Name: "test", Severity: domain.SeverityUnknown}, nil
	}}
	return httptransport.NewRouter(service, log.New(io.Discard, "", 0), limiter), calls
}

func assertRateLimitError(t *testing.T, request *http.Request, response *httptest.ResponseRecorder, status int) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, status, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var body struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.Message == "" {
		t.Errorf("invalid JSON error response: %s (decode error: %v)", response.Body.String(), err)
	}
	if status == 429 {
		retry, err := strconv.Atoi(response.Header().Get("Retry-After"))
		if err != nil || retry < 1 {
			t.Errorf("Retry-After = %q, want positive integer", response.Header().Get("Retry-After"))
		}
	}
	assertOpenAPIResponse(t, request, response)
}

type bodyReadProbe struct{ reads int }

func (b *bodyReadProbe) Read([]byte) (int, error) {
	b.reads++
	return 0, io.ErrUnexpectedEOF
}
