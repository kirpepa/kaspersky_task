package httptransport_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/legacy"

	"kasper/internal/domain"
	"kasper/internal/service"
	httptransport "kasper/internal/transport/http"
	api "kasper/internal/transport/http/openapi"
)

const testMD5 = "d41d8cd98f00b204e9800998ecf8427e"

type fakeService struct {
	call func() (domain.Threat, error)
}

func (f fakeService) Create(context.Context, service.CreateThreatInput) (domain.Threat, error) {
	return f.call()
}

func (f fakeService) GetByMD5(context.Context, string) (domain.Threat, error) {
	return f.call()
}

func (f fakeService) Update(context.Context, string, service.UpdateThreatInput) (domain.Threat, error) {
	return f.call()
}

func TestServiceErrorsBecomeHTTPResponses(t *testing.T) {
	tests := []struct {
		name, method, path, body string
		err                      error
		status                   int
		message                  string
	}{
		{"invalid MD5", "GET", "/info/" + testMD5, "", domain.ErrInvalidMD5, 400, "Invalid MD5"},
		{"invalid severity", "PUT", "/info/" + testMD5, `{"name":"test"}`, domain.ErrInvalidSeverity, 400, "Invalid request"},
		{"missing threat", "GET", "/info/" + testMD5, "", domain.ErrThreatNotFound, 404, "Threat not found"},
		{"missing update", "PUT", "/info/" + testMD5, `{"name":"test"}`, domain.ErrThreatNotFound, 404, "Threat not found"},
		{"duplicate", "POST", "/info", `{"md5":"` + testMD5 + `","name":"test"}`, domain.ErrThreatAlreadyExists, 409, "Threat already exists"},
		{"internal create failure", "POST", "/info", `{"md5":"` + testMD5 + `","name":"test"}`, errors.New("database password=secret"), 500, "Internal server error"},
		{"internal read failure", "GET", "/info/" + testMD5, "", errors.New("database password=secret"), 500, "Internal server error"},
		{"internal update failure", "PUT", "/info/" + testMD5, `{"name":"test"}`, errors.New("database password=secret"), 500, "Internal server error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			calls := 0
			service := fakeService{call: func() (domain.Threat, error) {
				calls++
				return domain.Threat{}, fmt.Errorf("private operation context: %w", tt.err)
			}}
			router := httptransport.NewRouter(service, log.New(&logs, "", 0), nil)
			response := httptest.NewRecorder()
			request := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			router.ServeHTTP(response, request)
			if calls != 1 {
				t.Fatalf("service calls = %d, want 1", calls)
			}
			assertErrorResponse(t, request, response, tt.status, tt.message)
			if strings.Contains(response.Body.String(), "private operation context") || strings.Contains(response.Body.String(), "secret") {
				t.Fatalf("response leaked internal details: %s", response.Body.String())
			}
			if tt.status == 500 && !strings.Contains(logs.String(), tt.err.Error()) {
				t.Errorf("internal error was not logged: %s", logs.String())
			}
		})
	}
}

func TestPanicReturnsJSONAndServerKeepsHandlingRequests(t *testing.T) {
	var logs bytes.Buffer
	calls := 0
	service := fakeService{call: func() (domain.Threat, error) {
		calls++
		if calls == 1 {
			panic("private panic details")
		}
		return domain.Threat{MD5: testMD5, Name: "test", Severity: domain.SeverityUnknown}, nil
	}}
	router := httptransport.NewRouter(service, log.New(&logs, "", 0), nil)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/info/"+testMD5, nil)
	router.ServeHTTP(response, request)
	assertErrorResponse(t, request, response, 500, "Internal server error")
	if strings.Contains(response.Body.String(), "private panic details") {
		t.Fatal("panic details leaked to client")
	}
	if !strings.Contains(logs.String(), "private panic details") {
		t.Fatal("panic details were not logged")
	}
	response = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/info/"+testMD5, nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("request after panic: status = %d, body = %s", response.Code, response.Body.String())
	}
	assertOpenAPIResponse(t, request, response)
}

func TestMalformedRequestNeverCallsService(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		for _, body := range []string{`{"name":`, `{"name":42}`, `null`, `{"name":"test"} {}`} {
			t.Run(method+"/"+body, func(t *testing.T) {
				called := false
				service := fakeService{call: func() (domain.Threat, error) {
					called = true
					return domain.Threat{}, nil
				}}
				router := httptransport.NewRouter(service, log.New(&bytes.Buffer{}, "", 0), nil)
				path := "/info"
				if method == http.MethodPut {
					path += "/" + testMD5
				}
				response := httptest.NewRecorder()
				request := httptest.NewRequest(method, path, strings.NewReader(body))
				router.ServeHTTP(response, request)
				assertErrorResponse(t, request, response, 400, "Invalid request")
				if called {
					t.Fatal("malformed request reached service")
				}
			})
		}
	}
}

func assertErrorResponse(t *testing.T, request *http.Request, response *httptest.ResponseRecorder, status int, message string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, status, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid error JSON: %v", err)
	}
	if body["message"] != message {
		t.Errorf("message = %v, want %q", body["message"], message)
	}
	if status == 500 {
		if len(body) != 1 {
			t.Errorf("internal error should expose only message: %v", body)
		}
	} else if details, ok := body["details"].(string); !ok || details == "" {
		t.Errorf("missing error details: %v", body)
	}
	assertOpenAPIResponse(t, request, response)
}

func assertOpenAPIResponse(t *testing.T, request *http.Request, response *httptest.ResponseRecorder) {
	t.Helper()
	spec, err := api.GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	router, err := legacy.NewRouter(spec)
	if err != nil {
		t.Fatal(err)
	}
	route, params, err := router.FindRoute(request)
	if err != nil {
		t.Fatal(err)
	}
	input := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{Request: request, Route: route, PathParams: params},
		Status:                 response.Code,
		Header:                 response.Header(),
		Options:                &openapi3filter.Options{IncludeResponseStatus: true},
	}
	input.SetBodyBytes(response.Body.Bytes())
	if err := openapi3filter.ValidateResponse(request.Context(), input); err != nil {
		t.Errorf("%s %s response violates OpenAPI: %v", request.Method, request.URL.Path, err)
	}
}
