// Package openapi contains HTTP types and server bindings generated from the API contract.
package openapi

//go:generate env GOTOOLCHAIN=go1.24.4 go tool oapi-codegen -config ../../../../api/oapi-codegen.yaml -o api.gen.go ../../../../api/openapi.yaml
