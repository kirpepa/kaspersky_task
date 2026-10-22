package integration_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/legacy"

	api "kasper/internal/transport/http/openapi"
)

func TestJSONRequestsWithoutContentTypeRemainSupported(t *testing.T) {
	server := newServer(t)
	tests := []struct {
		method, path, body string
		status             int
	}{
		{"POST", "/info", `{"md5":"` + md5 + `","name":"created"}`, 201},
		{"PUT", "/info/" + md5, `{"name":"updated","description":"","severity":"unknown"}`, 200},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, server.URL+tt.path, strings.NewReader(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			response, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != tt.status {
				t.Fatalf("request without Content-Type: status = %d, want %d; body = %s", response.StatusCode, tt.status, body)
			}
			assertOpenAPIResponse(t, req, response.StatusCode, response.Header, body)
			name := "created"
			if tt.method == "PUT" {
				name = "updated"
			}
			assertThreat(t, body, threat{MD5: md5, Name: name, Severity: "unknown"})
		})
	}
}

func TestUnknownCaseCollidingFieldsDoNotOverrideKnownFields(t *testing.T) {
	server := newServer(t)
	body := `{"md5":"` + md5 + `","MD5":"` + otherMD5 + `","name":"first","Name":"second","description":"original","Description":"replacement","severity":"high","SEVERITY":null}`
	want := threat{MD5: md5, Name: "first", Description: "original", Severity: "high"}
	assertThreat(t, request(t, server, "POST", "/info", body, 201), want)
	assertThreat(t, request(t, server, "GET", "/info/"+md5, "", 200), want)
	request(t, server, "GET", "/info/"+otherMD5, "", 404)

	body = `{"name":"updated first","Name":"updated second","description":"updated original","Description":"updated replacement","severity":"critical","SEVERITY":null,"MD5":"` + otherMD5 + `"}`
	want = threat{MD5: md5, Name: "updated first", Description: "updated original", Severity: "critical"}
	assertThreat(t, request(t, server, "PUT", "/info/"+md5, body, 200), want)
	assertThreat(t, request(t, server, "GET", "/info/"+md5, "", 200), want)
	request(t, server, "GET", "/info/"+otherMD5, "", 404)
}

func TestURLEncodedMD5MatchesDecodedIdentity(t *testing.T) {
	server := newServer(t)
	request(t, server, "POST", "/info", `{"md5":"`+md5+`","name":"original"}`, 201)
	encodedPath := "/info/%64" + md5[1:]
	want := threat{MD5: md5, Name: "original", Severity: "unknown"}
	assertThreat(t, request(t, server, "GET", encodedPath, "", 200), want)

	want.Name, want.Severity = "updated", "low"
	assertThreat(t, request(t, server, "PUT", encodedPath, `{"name":"updated","severity":"low"}`, 200), want)
	assertThreat(t, request(t, server, "GET", "/info/"+md5, "", 200), want)
}

func TestHEADPreservesGETStatusAndContentTypeWithoutBody(t *testing.T) {
	server := newServer(t)
	request(t, server, "POST", "/info", `{"md5":"`+md5+`","name":"original"}`, 201)
	tests := []struct {
		name, path string
		status     int
	}{
		{"existing", "/info/" + md5, 200},
		{"missing", "/info/" + otherMD5, 404},
		{"invalid MD5", "/info/invalid", 400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request(t, server, "GET", tt.path, "", tt.status)
			response, err := server.Client().Head(server.URL + tt.path)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != tt.status {
				t.Errorf("HEAD status = %d, want GET status %d", response.StatusCode, tt.status)
			}
			if got := response.Header.Get("Content-Type"); got != "application/json" {
				t.Errorf("HEAD Content-Type = %q, want application/json", got)
			}
			if len(body) != 0 {
				t.Errorf("HEAD returned body: %s", body)
			}
		})
	}
}

func assertOpenAPIResponse(t *testing.T, request *http.Request, status int, header http.Header, body []byte) {
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
		Status:                 status,
		Header:                 header,
		Options:                &openapi3filter.Options{IncludeResponseStatus: true},
	}
	input.SetBodyBytes(body)
	if err := openapi3filter.ValidateResponse(request.Context(), input); err != nil {
		t.Errorf("%s %s response violates OpenAPI: %v", request.Method, request.URL.Path, err)
	}
}
