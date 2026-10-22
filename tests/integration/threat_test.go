package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"kasper/internal/repository/memory"
	"kasper/internal/repository/postgres"
	"kasper/internal/service"
	httptransport "kasper/internal/transport/http"
)

const (
	md5      = "d41d8cd98f00b204e9800998ecf8427e"
	otherMD5 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

type threat struct {
	MD5         string `json:"md5"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

func TestThreatLifecycle(t *testing.T) {
	server := newServer(t)
	upper := strings.ToUpper(md5)
	created := request(t, server, "POST", "/info", `{"md5":"`+upper+`","name":"","extra":{"allowed":true}}`, 201)
	want := threat{MD5: md5, Severity: "unknown"}
	assertThreat(t, created, want)
	assertThreat(t, request(t, server, "GET", "/info/"+md5, "", 200), want)

	updated := request(t, server, "PUT", "/info/"+upper, `{"name":"Trojan","description":"Observed in sample","severity":"high"}`, 200)
	want = threat{MD5: md5, Name: "Trojan", Description: "Observed in sample", Severity: "high"}
	assertThreat(t, updated, want)
	assertThreat(t, request(t, server, "GET", "/info/"+upper, "", 200), want)

	// PUT replaces optional fields; extra properties cannot change the path identity.
	reset := request(t, server, "PUT", "/info/"+md5, `{"name":"","md5":"`+otherMD5+`","extra":42}`, 200)
	want = threat{MD5: md5, Severity: "unknown"}
	assertThreat(t, reset, want)
	assertThreat(t, request(t, server, "GET", "/info/"+md5, "", 200), want)
	request(t, server, "GET", "/info/"+otherMD5, "", 404)
}

func TestDuplicateCreatePreservesExistingThreat(t *testing.T) {
	server := newServer(t)
	want := threat{MD5: md5, Name: "original", Description: "keep", Severity: "critical"}
	request(t, server, "POST", "/info", `{"md5":"`+md5+`","name":"original","description":"keep","severity":"critical"}`, 201)
	request(t, server, "POST", "/info", `{"md5":"`+strings.ToUpper(md5)+`","name":"replacement"}`, 409)
	assertThreat(t, request(t, server, "GET", "/info/"+md5, "", 200), want)
}

func TestUpdateMissingThreatDoesNotCreateIt(t *testing.T) {
	server := newServer(t)
	request(t, server, "PUT", "/info/"+md5, `{"name":"missing","severity":"low"}`, 404)
	request(t, server, "GET", "/info/"+md5, "", 404)
}

func TestInvalidRequestsPreserveState(t *testing.T) {
	commonBodies := []struct{ name, body string }{
		{"empty body", ""},
		{"whitespace body", " \n\t"},
		{"null body", `null`},
		{"array body", `[]`},
		{"string body", `"text"`},
		{"number body", `42`},
		{"boolean body", `true`},
		{"invalid JSON", `{"name":`},
		{"multiple objects", `{"md5":"` + otherMD5 + `","name":"test"} {}`},
		{"trailing null", `{"md5":"` + otherMD5 + `","name":"test"} null`},
		{"trailing array", `{"md5":"` + otherMD5 + `","name":"test"} []`},
		{"trailing garbage", `{"md5":"` + otherMD5 + `","name":"test"} nope`},
		{"missing name", `{"md5":"` + otherMD5 + `"}`},
		{"null name", `{"md5":"` + otherMD5 + `","name":null}`},
		{"wrong name type", `{"md5":"` + otherMD5 + `","name":123}`},
		{"null description", `{"md5":"` + otherMD5 + `","name":"test","description":null}`},
		{"wrong description type", `{"md5":"` + otherMD5 + `","name":"test","description":[]}`},
		{"null severity", `{"md5":"` + otherMD5 + `","name":"test","severity":null}`},
		{"wrong severity type", `{"md5":"` + otherMD5 + `","name":"test","severity":false}`},
		{"unknown severity", `{"md5":"` + otherMD5 + `","name":"test","severity":"urgent"}`},
		{"uppercase severity", `{"md5":"` + otherMD5 + `","name":"test","severity":"HIGH"}`},
		{"empty severity", `{"md5":"` + otherMD5 + `","name":"test","severity":""}`},
	}
	type testCase struct{ name, method, path, body string }
	var tests []testCase
	for _, body := range commonBodies {
		tests = append(tests,
			testCase{"POST/" + body.name, "POST", "/info", body.body},
			testCase{"PUT/" + body.name, "PUT", "/info/" + md5, body.body},
		)
	}
	tests = append(tests,
		testCase{"POST/missing MD5", "POST", "/info", `{"name":"test"}`},
		testCase{"POST/null MD5", "POST", "/info", `{"md5":null,"name":"test"}`},
		testCase{"POST/wrong MD5 type", "POST", "/info", `{"md5":42,"name":"test"}`},
		testCase{"POST/empty MD5", "POST", "/info", `{"md5":"","name":"test"}`},
	)
	for _, invalidMD5 := range []string{"short", strings.Repeat("a", 33), strings.Repeat("g", 32), " " + md5, md5 + "\n"} {
		path := "/info/" + url.PathEscape(invalidMD5)
		tests = append(tests,
			testCase{"POST/MD5=" + invalidMD5, "POST", "/info", fmt.Sprintf(`{"md5":%q,"name":"test"}`, invalidMD5)},
			testCase{"GET/MD5=" + invalidMD5, "GET", path, ""},
			testCase{"PUT/MD5=" + invalidMD5, "PUT", path, `{"name":"test"}`},
		)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newServer(t)
			want := threat{MD5: md5, Name: "original", Description: "keep", Severity: "medium"}
			request(t, server, "POST", "/info", `{"md5":"`+md5+`","name":"original","description":"keep","severity":"medium"}`, 201)
			request(t, server, tt.method, tt.path, tt.body, 400)
			assertThreat(t, request(t, server, "GET", "/info/"+md5, "", 200), want)
			request(t, server, "GET", "/info/"+otherMD5, "", 404)
		})
	}
}

func TestConcurrentDuplicateCreatesHaveSingleWinner(t *testing.T) {
	server := newServer(t)
	const count = 20
	type result struct {
		status  int
		request *http.Request
		header  http.Header
		body    []byte
		err     error
	}
	results := make(chan result, count)
	start := make(chan struct{})
	for i := range count {
		go func() {
			<-start
			hash := md5
			if i%2 == 0 {
				hash = strings.ToUpper(hash)
			}
			body := fmt.Sprintf(`{"md5":%q,"name":"writer-%d"}`, hash, i)
			response, err := server.Client().Post(server.URL+"/info", "application/json", strings.NewReader(body))
			if err != nil {
				results <- result{err: err}
				return
			}
			defer response.Body.Close()
			data, err := io.ReadAll(response.Body)
			results <- result{status: response.StatusCode, request: response.Request, header: response.Header, body: data, err: err}
		}()
	}
	close(start)
	winners := 0
	var winner threat
	for range count {
		result := <-results
		if result.err != nil {
			t.Errorf("concurrent request failed: %v", result.err)
			continue
		}
		assertOpenAPIResponse(t, result.request, result.status, result.header, result.body)
		switch result.status {
		case http.StatusCreated:
			winners++
			if err := json.Unmarshal(result.body, &winner); err != nil {
				t.Errorf("invalid created response: %v", err)
			}
		case http.StatusConflict:
			var response map[string]any
			if err := json.Unmarshal(result.body, &response); err != nil || response["message"] != "Threat already exists" {
				t.Errorf("invalid conflict response: %s", result.body)
			}
		default:
			t.Errorf("unexpected concurrent response: %d %s", result.status, result.body)
		}
	}
	if winners != 1 {
		t.Fatalf("successful creates = %d, want exactly 1", winners)
	}
	assertThreat(t, request(t, server, "GET", "/info/"+md5, "", 200), winner)
}

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	var repository service.ThreatRepository = memory.NewThreatRepository()
	if os.Getenv("TEST_DATABASE_URL") != "" {
		pool, _ := newPostgresPool(t)
		repository = postgres.NewThreatRepository(pool)
	}
	return newServerWithRepository(t, repository)
}

func newServerWithRepository(t *testing.T, repository service.ThreatRepository) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(httptransport.NewRouter(service.NewThreatService(repository), log.New(io.Discard, "", 0), nil))
	server.Client().Timeout = 5 * time.Second
	t.Cleanup(server.Close)
	return server
}

func request(t *testing.T, server *httptest.Server, method, path, body string, status int) []byte {
	t.Helper()
	req, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
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
	if response.StatusCode != status {
		t.Fatalf("%s %s: status = %d, want %d; body = %s", method, path, response.StatusCode, status, data)
	}
	if got := response.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if !json.Valid(data) {
		t.Fatalf("invalid JSON response: %s", data)
	}
	assertOpenAPIResponse(t, req, response.StatusCode, response.Header, data)
	if status >= 400 {
		var response map[string]any
		if err := json.Unmarshal(data, &response); err != nil {
			t.Fatal(err)
		}
		if message, ok := response["message"].(string); !ok || message == "" {
			t.Errorf("error response has no message: %s", data)
		}
	}
	return data
}

func assertThreat(t *testing.T, data []byte, want threat) {
	t.Helper()
	var got threat
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("threat = %+v, want %+v", got, want)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"md5", "name", "description", "severity"} {
		if _, ok := fields[name]; !ok {
			t.Errorf("response missing field %q: %s", name, data)
		}
	}
}
