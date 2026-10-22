package domain

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Text limits count Unicode code points rather than UTF-8 bytes.
const (
	MaxNameLength        = 256
	MaxDescriptionLength = 4096
)

type Severity string

const (
	SeverityUnknown  Severity = "unknown"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Threat struct {
	MD5         string
	Name        string
	Description string
	Severity    Severity
}

// ValidateThreatText accepts empty fields and rejects NUL and oversized text.
// Validation errors wrap ErrInvalidText and identify the affected field.
func ValidateThreatText(name, description string) error {
	for _, field := range []struct {
		name  string
		value string
		limit int
	}{
		{"name", name, MaxNameLength},
		{"description", description, MaxDescriptionLength},
	} {
		if strings.ContainsRune(field.value, '\x00') {
			return fmt.Errorf("%w: %s must not contain U+0000", ErrInvalidText, field.name)
		}
		if utf8.RuneCountInString(field.value) > field.limit {
			return fmt.Errorf("%w: %s must contain at most %d Unicode code points", ErrInvalidText, field.name, field.limit)
		}
	}
	return nil
}

func NormalizeMD5(value string) (string, error) {
	if len(value) != 32 {
		return "", ErrInvalidMD5
	}
	for _, ch := range value {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return "", ErrInvalidMD5
		}
	}
	return strings.ToLower(value), nil
}

func ParseSeverity(value string) (Severity, error) {
	severity := Severity(value)
	switch severity {
	case SeverityUnknown, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return severity, nil
	default:
		return "", ErrInvalidSeverity
	}
}
