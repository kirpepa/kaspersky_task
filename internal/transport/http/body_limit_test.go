package httptransport_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"kasper/internal/domain"
	httptransport "kasper/internal/transport/http"
)

func TestBodySizeBoundaries(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		for _, knownLength := range []bool{true, false} {
			for _, offset := range []int{-1, 0, 1} {
				t.Run(fmt.Sprintf("%s/known-length=%t/limit%+d", method, knownLength, offset), func(t *testing.T) {
					size := int(httptransport.MaxRequestBodyBytes) + offset
					body := &observedRequestBody{Reader: strings.NewReader(paddedBody(method, size))}
					calls := 0
					router := httptransport.NewRouter(fakeService{call: func() (domain.Threat, error) {
						calls++
						return domain.Threat{MD5: testMD5, Name: "test", Severity: domain.SeverityUnknown}, nil
					}}, log.New(io.Discard, "", 0), nil)
					request := httptest.NewRequest(method, bodyLimitPath(method), body)
					request.ContentLength = -1
					if knownLength {
						request.ContentLength = int64(size)
					}
					response := httptest.NewRecorder()
					router.ServeHTTP(response, request)
					if offset > 0 {
						assertErrorResponse(t, request, response, 413, "Request body too large")
						if calls != 0 {
							t.Fatal("oversized body reached service")
						}
						if knownLength && body.bytesRead != 0 {
							t.Errorf("known oversized body read %d bytes, want 0", body.bytesRead)
						}
						if body.closed {
							t.Error("oversized body was closed before writing error")
						}
						if response.Header().Get("Connection") != "close" {
							t.Error("oversized HTTP/1 request did not close connection")
						}
					} else {
						want := http.StatusOK
						if method == http.MethodPost {
							want = http.StatusCreated
						}
						if response.Code != want || calls != 1 {
							t.Fatalf("status = %d, calls = %d; want %d, 1; body = %s", response.Code, calls, want, response.Body.String())
						}
						assertOpenAPIResponse(t, request, response)
					}
				})
			}
		}
	}
}

func TestUnknownOrMisreportedLengthCannotBypassBodyLimit(t *testing.T) {
	for _, contentLength := range []int64{-1, 1} {
		t.Run(fmt.Sprintf("content-length=%d", contentLength), func(t *testing.T) {
			// The request body is much larger than the limit; at most one extra
			// byte is needed to distinguish a full body from an oversized one.
			body := &observedRequestBody{Reader: strings.NewReader(paddedBody(http.MethodPost, 8<<20))}
			router := httptransport.NewRouter(fakeService{call: func() (domain.Threat, error) {
				t.Fatal("oversized body reached service")
				return domain.Threat{}, nil
			}}, log.New(io.Discard, "", 0), nil)
			request := httptest.NewRequest(http.MethodPost, "/info", body)
			request.ContentLength = contentLength
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			assertErrorResponse(t, request, response, 413, "Request body too large")
			if got, want := body.bytesRead, int(httptransport.MaxRequestBodyBytes)+1; got != want {
				t.Errorf("body bytes read = %d, want %d", got, want)
			}
		})
	}
}

func TestBodyReadErrorsAreClassifiedWithoutClosingBody(t *testing.T) {
	for _, test := range []struct {
		name, message string
		err           error
		status        int
	}{
		{"timeout", "Request timeout", &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}, 408},
		{"broken body", "Invalid request", io.ErrUnexpectedEOF, 400},
	} {
		for _, method := range []string{http.MethodPost, http.MethodPut} {
			t.Run(method+"/"+test.name, func(t *testing.T) {
				body := &observedRequestBody{Reader: failingBodyReader{err: test.err}}
				router := httptransport.NewRouter(fakeService{call: func() (domain.Threat, error) {
					t.Fatal("unreadable body reached service")
					return domain.Threat{}, nil
				}}, log.New(io.Discard, "", 0), nil)
				request := httptest.NewRequest(method, bodyLimitPath(method), body)
				response := httptest.NewRecorder()
				router.ServeHTTP(response, request)
				assertErrorResponse(t, request, response, test.status, test.message)
				if body.closed {
					t.Error("unreadable body was closed before writing error")
				}
				if test.status == 408 && response.Header().Get("Connection") != "close" {
					t.Error("timed out HTTP/1 request did not close connection")
				}
			})
		}
	}
}

func TestServiceTimeoutIsNotARequestReadTimeout(t *testing.T) {
	for _, err := range []error{context.DeadlineExceeded, &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}} {
		router := httptransport.NewRouter(fakeService{call: func() (domain.Threat, error) {
			return domain.Threat{}, fmt.Errorf("database operation: %w", err)
		}}, log.New(io.Discard, "", 0), nil)
		request := httptest.NewRequest(http.MethodPost, "/info", strings.NewReader(`{"md5":"`+testMD5+`","name":"test"}`))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		assertErrorResponse(t, request, response, 500, "Internal server error")
	}
}

func TestInvalidTextFromServiceBecomesBadRequest(t *testing.T) {
	err := domain.ValidateThreatText("a\x00b", "")
	if !errors.Is(err, domain.ErrInvalidText) {
		t.Fatal("expected invalid text error")
	}
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		router := httptransport.NewRouter(fakeService{call: func() (domain.Threat, error) {
			return domain.Threat{}, err
		}}, log.New(io.Discard, "", 0), nil)
		request := httptest.NewRequest(method, bodyLimitPath(method), strings.NewReader(`{"md5":"`+testMD5+`","name":"test"}`))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		assertErrorResponse(t, request, response, 400, "Invalid request")
		if !strings.Contains(response.Body.String(), "name must not contain U+0000") {
			t.Errorf("missing field details: %s", response.Body.String())
		}
	}
}

func TestRateLimitRunsBeforeKnownBodySizeCheck(t *testing.T) {
	router, calls := newRateLimitedRouter(t, 1)
	request := httptest.NewRequest(http.MethodGet, "/info/"+testMD5, nil)
	router.ServeHTTP(httptest.NewRecorder(), request)
	body := &observedRequestBody{Reader: strings.NewReader("unread")}
	request = httptest.NewRequest(http.MethodPost, "/info", body)
	request.ContentLength = httptransport.MaxRequestBodyBytes + 1
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertRateLimitError(t, request, response, 429)
	if body.bytesRead != 0 || calls.Load() != 1 {
		t.Fatalf("rate limited body read %d bytes, total service calls %d", body.bytesRead, calls.Load())
	}
}

func bodyLimitPath(method string) string {
	if method == http.MethodPut {
		return "/info/" + testMD5
	}
	return "/info"
}

func paddedBody(method string, size int) string {
	prefix := `{"name":"test","ignored":"`
	if method == http.MethodPost {
		prefix = `{"md5":"` + testMD5 + `","name":"test","ignored":"`
	}
	return prefix + strings.Repeat("x", size-len(prefix)-2) + `"}`
}

type observedRequestBody struct {
	io.Reader
	bytesRead int
	closed    bool
}

func (r *observedRequestBody) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.bytesRead += n
	return n, err
}

func (r *observedRequestBody) Close() error {
	r.closed = true
	return nil
}

type failingBodyReader struct{ err error }

func (r failingBodyReader) Read([]byte) (int, error) { return 0, r.err }
