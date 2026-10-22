package domain_test

import (
	"errors"
	"strings"
	"testing"

	"kasper/internal/domain"
)

func TestNormalizeMD5(t *testing.T) {
	t.Parallel()
	const normalized = "d41d8cd98f00b204e9800998ecf8427e"
	tests := []struct {
		name, input, want string
	}{
		{"lowercase", normalized, normalized},
		{"uppercase", strings.ToUpper(normalized), normalized},
		{"mixed case", "D41d8Cd98f00B204e9800998eCF8427e", normalized},
		{"all hex digits", "0123456789abcdef0123456789ABCDEF", "0123456789abcdef0123456789abcdef"},
		{"empty", "", ""},
		{"short", normalized[:31], ""},
		{"long", normalized + "0", ""},
		{"non hex", "g" + normalized[1:], ""},
		{"whitespace", " " + normalized[1:], ""},
		{"unicode with 32 bytes", strings.Repeat("é", 16), ""},
		{"unicode with 32 characters", strings.Repeat("а", 32), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := domain.NormalizeMD5(tt.input)
			if tt.want == "" {
				if !errors.Is(err, domain.ErrInvalidMD5) || got != "" {
					t.Fatalf("NormalizeMD5(%q) = %q, %v; want empty value and ErrInvalidMD5", tt.input, got, err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("NormalizeMD5(%q) = %q, %v; want %q, nil", tt.input, got, err, tt.want)
			}
		})
	}
}

func TestParseSeverity(t *testing.T) {
	t.Parallel()
	valid := map[string]domain.Severity{
		"unknown": domain.SeverityUnknown, "low": domain.SeverityLow,
		"medium": domain.SeverityMedium, "high": domain.SeverityHigh,
		"critical": domain.SeverityCritical,
	}
	for input, want := range valid {
		t.Run(input, func(t *testing.T) {
			if got, err := domain.ParseSeverity(input); err != nil || got != want {
				t.Fatalf("ParseSeverity(%q) = %q, %v; want %q, nil", input, got, err, want)
			}
		})
	}
	for _, input := range []string{"", "HIGH", " high", "high ", "urgent"} {
		t.Run("invalid/"+input, func(t *testing.T) {
			got, err := domain.ParseSeverity(input)
			if !errors.Is(err, domain.ErrInvalidSeverity) || got != "" {
				t.Fatalf("ParseSeverity(%q) = %q, %v; want empty value and ErrInvalidSeverity", input, got, err)
			}
		})
	}
}

func TestValidateThreatText(t *testing.T) {
	t.Parallel()
	fields := []struct {
		name  string
		limit int
	}{
		{"name", domain.MaxNameLength},
		{"description", domain.MaxDescriptionLength},
	}
	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			tests := []struct {
				name, value string
				invalid     bool
			}{
				{"empty", "", false},
				{"multiline", "line 1\nline 2\r\n\t", false},
				{"below limit", strings.Repeat("界", field.limit-1), false},
				{"at limit", strings.Repeat("界", field.limit), false},
				{"at limit supplementary Unicode", strings.Repeat("😀", field.limit), false},
				{"over limit", strings.Repeat("界", field.limit+1), true},
				{"combining marks count separately", strings.Repeat("e\u0301", field.limit/2) + "x", true},
				{"NUL only", "\x00", true},
				{"NUL prefix", "\x00text", true},
				{"NUL middle", "a\x00b", true},
				{"NUL suffix", "text\x00", true},
				{"NUL after newline", "text\n\x00", true},
			}
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					name, description := "valid", "valid"
					if field.name == "name" {
						name = tt.value
					} else {
						description = tt.value
					}
					err := domain.ValidateThreatText(name, description)
					if !tt.invalid {
						if err != nil {
							t.Fatalf("valid text rejected: %v", err)
						}
						return
					}
					if !errors.Is(err, domain.ErrInvalidText) {
						t.Fatalf("invalid text error = %v; want ErrInvalidText", err)
					}
					if !strings.Contains(err.Error(), field.name) {
						t.Fatalf("error does not identify %s: %v", field.name, err)
					}
				})
			}
		})
	}
}
