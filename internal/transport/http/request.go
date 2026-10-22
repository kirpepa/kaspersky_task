package httptransport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	nethttpmiddleware "github.com/oapi-codegen/nethttp-middleware"

	"kasper/internal/domain"
)

// MaxRequestBodyBytes limits the complete JSON body, including unknown fields.
const MaxRequestBodyBytes int64 = 64 << 10

type requestError struct {
	details string
}

type requestBodyError struct {
	err error
}

func (e *requestBodyError) Error() string { return e.err.Error() }

func (e *requestBodyError) Unwrap() error { return e.err }

func (h *handler) writeBodyError(w http.ResponseWriter, r *http.Request, err error) {
	var tooLarge *http.MaxBytesError
	var networkErr net.Error
	if r.ProtoMajor == 1 && (errors.As(err, &tooLarge) || errors.As(err, &networkErr) && networkErr.Timeout()) {
		// Do not drain an oversized or stalled body before sending the error.
		w.Header().Set("Connection", "close")
	}
	h.writeError(w, &requestBodyError{err: err})
}

func (e *requestError) Error() string {
	return e.details
}

// prepareJSONBody checks framing that a single json.Decoder.Decode would ignore.
// Field types, required fields and constraints are checked against OpenAPI next.
func (h *handler) prepareJSONBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.Clone(r.Context())
		// ServeMux already decoded the path and maps HEAD to GET. Validate the
		// same operation and decoded identity instead of the raw URL spelling.
		r.URL.RawPath = ""
		if r.Method == http.MethodHead {
			r.Method = http.MethodGet
		}
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			next.ServeHTTP(w, r)
			return
		}
		if r.ContentLength > MaxRequestBodyBytes {
			h.writeBodyError(w, r, &http.MaxBytesError{Limit: MaxRequestBodyBytes})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
		data, err := io.ReadAll(r.Body)
		if err != nil {
			h.writeBodyError(w, r, err)
			return
		}
		_ = r.Body.Close()
		if !json.Valid(data) {
			h.writeError(w, &requestError{details: "Request body must contain exactly one valid JSON value"})
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(data))
		// Earlier clients could omit Content-Type; keep accepting their JSON bodies.
		if r.Header.Get("Content-Type") == "" {
			r.Header.Set("Content-Type", "application/json")
		}
		next.ServeHTTP(w, r)
	})
}

// bindJSONFields runs after validation. OpenAPI property names are case-sensitive,
// whereas encoding/json also matches Go fields ignoring case. Ignore properties
// outside the schema before the generated decoder can mistake them for API fields.
func (h *handler) bindJSONFields(spec *openapi3.T) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, pattern, _ := strings.Cut(r.Pattern, " ")
			path := spec.Paths.Value(pattern)
			if path == nil {
				h.writeError(w, fmt.Errorf("generated route missing in OpenAPI: %s", r.Pattern))
				return
			}
			operation := path.GetOperation(r.Method)
			if operation == nil || operation.RequestBody == nil {
				next.ServeHTTP(w, r)
				return
			}
			schema := operation.RequestBody.Value.Content.Get("application/json").Schema.Value
			var fields map[string]json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&fields); err != nil {
				h.writeError(w, fmt.Errorf("decode validated request: %w", err))
				return
			}
			_ = r.Body.Close()
			for name := range fields {
				if _, known := schema.Properties[name]; !known {
					delete(fields, name)
				}
			}
			data, err := json.Marshal(fields)
			if err != nil {
				h.writeError(w, fmt.Errorf("encode validated request: %w", err))
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(data))
			r.ContentLength = int64(len(data))
			r.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(data)), nil
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (h *handler) writeValidationError(_ context.Context, err error, w http.ResponseWriter, _ *http.Request, opts nethttpmiddleware.ErrorHandlerOpts) {
	if opts.StatusCode >= http.StatusInternalServerError {
		h.writeError(w, err)
		return
	}
	var requestErr *openapi3filter.RequestError
	if errors.As(err, &requestErr) && requestErr.Parameter != nil && requestErr.Parameter.Name == "md5" {
		h.writeError(w, domain.ErrInvalidMD5)
		return
	}
	var schemaErr *openapi3.SchemaError
	if errors.As(err, &schemaErr) {
		fields := schemaErr.JSONPointer()
		if len(fields) == 1 && fields[0] == "md5" && schemaErr.SchemaField == "pattern" {
			h.writeError(w, domain.ErrInvalidMD5)
			return
		}
		details := schemaErr.Reason
		if len(fields) != 0 {
			details = "Field " + strings.Join(fields, ".") + ": " + details
		}
		h.writeError(w, &requestError{details: details})
		return
	}
	// The full validation error may include a dump of the schema and request body.
	// Return its first line while keeping internal failures on the server side.
	details, _, _ := strings.Cut(err.Error(), "\n")
	h.writeError(w, &requestError{details: details})
}
