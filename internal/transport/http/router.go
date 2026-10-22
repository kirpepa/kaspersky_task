package httptransport

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3filter"
	nethttpmiddleware "github.com/oapi-codegen/nethttp-middleware"

	api "kasper/internal/transport/http/openapi"
)

// NewRouter applies the optional IP limiter before reading API request bodies.
// A nil limiter is useful when testing the API's business behavior in isolation.
func NewRouter(service ThreatService, logger *log.Logger, limiter *IPRateLimiter) http.Handler {
	h := &handler{service: service, logger: logger}
	spec, err := api.GetSwagger()
	if err != nil {
		panic(fmt.Errorf("load generated OpenAPI contract: %w", err))
	}
	if err := spec.Validate(context.Background()); err != nil {
		panic(fmt.Errorf("validate generated OpenAPI contract: %w", err))
	}
	validator := nethttpmiddleware.OapiRequestValidatorWithOptions(spec, &nethttpmiddleware.Options{
		// Defaults belong to the service; null must not become a default value.
		Options:              openapi3filter.Options{SkipSettingDefaults: true},
		ErrorHandlerWithOpts: h.writeValidationError,
	})
	requestErrorHandler := func(w http.ResponseWriter, _ *http.Request, err error) {
		h.writeError(w, &requestError{details: err.Error()})
	}
	strict := api.NewStrictHandlerWithOptions(h, nil, api.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: requestErrorHandler,
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			h.writeError(w, err)
		},
	})
	middlewares := []api.MiddlewareFunc{h.bindJSONFields(spec), validator, h.prepareJSONBody}
	if limiter != nil {
		middlewares = append(middlewares, h.rateLimit(limiter))
	}
	router := api.HandlerWithOptions(strict, api.StdHTTPServerOptions{
		ErrorHandlerFunc: requestErrorHandler,
		// Generated wrappers apply the last middleware first. Only matched API
		// routes are validated, preserving ServeMux's 404 and 405 handling.
		Middlewares: middlewares,
	})
	return h.recoverErrors(router)
}
