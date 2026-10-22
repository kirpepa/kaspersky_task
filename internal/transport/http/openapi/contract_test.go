package openapi_test

import (
	"context"
	"strings"
	"testing"

	"kasper/internal/domain"
	api "kasper/internal/transport/http/openapi"
)

func TestThreatTextRequestConstraints(t *testing.T) {
	t.Parallel()
	spec, err := api.GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	if err := spec.Validate(context.Background()); err != nil {
		t.Fatalf("invalid OpenAPI document: %v", err)
	}
	for _, schemaName := range []string{"ThreatCreateRequest", "ThreatUpdateRequest"} {
		for _, field := range []struct {
			name  string
			limit int
		}{
			{"name", domain.MaxNameLength},
			{"description", domain.MaxDescriptionLength},
		} {
			t.Run(schemaName+"/"+field.name, func(t *testing.T) {
				schema := spec.Components.Schemas[schemaName].Value
				property := schema.Properties[field.name].Value
				if property.MaxLength == nil || *property.MaxLength != uint64(field.limit) {
					t.Fatalf("OpenAPI maxLength does not match domain limit %d", field.limit)
				}
				tests := []struct {
					name, value string
					invalid     bool
				}{
					{"empty", "", false},
					{"multiline", "first\nsecond\r\n\t", false},
					{"Unicode at limit", strings.Repeat("😀", field.limit), false},
					{"Unicode over limit", strings.Repeat("😀", field.limit+1), true},
					{"NUL", "a\x00b", true},
					{"NUL after newline", "line\n\x00", true},
				}
				for _, tt := range tests {
					t.Run(tt.name, func(t *testing.T) {
						body := map[string]any{"name": "valid", "description": "valid"}
						if schemaName == "ThreatCreateRequest" {
							body["md5"] = "d41d8cd98f00b204e9800998ecf8427e"
						}
						body[field.name] = tt.value
						err := schema.VisitJSON(body)
						if (err != nil) != tt.invalid {
							t.Fatalf("invalid = %t; want %t", err != nil, tt.invalid)
						}
					})
				}
			})
		}
	}
}

func TestThreatResponseAllowsPreviouslyStoredLongFields(t *testing.T) {
	t.Parallel()
	spec, err := api.GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"md5":         "d41d8cd98f00b204e9800998ecf8427e",
		"name":        strings.Repeat("界", domain.MaxNameLength+1),
		"description": strings.Repeat("界", domain.MaxDescriptionLength+1),
		"severity":    "unknown",
	}
	if err := spec.Components.Schemas["ThreatResponse"].Value.VisitJSON(body); err != nil {
		t.Fatalf("existing row with long text violates response contract: %v", err)
	}
}
