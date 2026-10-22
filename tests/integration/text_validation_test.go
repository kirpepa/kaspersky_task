package integration_test

import (
	"encoding/json"
	"strings"
	"testing"

	"kasper/internal/domain"
	"kasper/internal/repository/postgres"
)

func TestTextLengthBoundaries(t *testing.T) {
	for _, character := range []string{"a", "Ж", "🔒"} {
		t.Run(character, func(t *testing.T) {
			server := newServer(t)
			want := threat{
				MD5:         md5,
				Name:        strings.Repeat(character, domain.MaxNameLength),
				Description: strings.Repeat(character, domain.MaxDescriptionLength),
				Severity:    "unknown",
			}
			body := textRequestJSON(t, md5, want.Name, want.Description)
			assertThreat(t, request(t, server, "POST", "/info", body, 201), want)
			assertThreat(t, request(t, server, "PUT", "/info/"+md5, body, 200), want)
			for _, field := range []string{"name", "description"} {
				t.Run(field+" over limit", func(t *testing.T) {
					name, description := want.Name, want.Description
					if field == "name" {
						name += character
					} else {
						description += character
					}
					invalid := textRequestJSON(t, otherMD5, name, description)
					request(t, server, "POST", "/info", invalid, 400)
					request(t, server, "PUT", "/info/"+md5, invalid, 400)
					request(t, server, "GET", "/info/"+otherMD5, "", 404)
					assertThreat(t, request(t, server, "GET", "/info/"+md5, "", 200), want)
				})
			}
		})
	}
}

func TestPostgresRejectsNULWithoutChangingData(t *testing.T) {
	pool, _ := newPostgresPool(t)
	server := newServerWithRepository(t, postgres.NewThreatRepository(pool))
	want := threat{MD5: md5, Name: "original", Description: "keep", Severity: "unknown"}
	request(t, server, "POST", "/info", textRequestJSON(t, md5, want.Name, want.Description), 201)
	for _, field := range []string{"name", "description"} {
		t.Run(field, func(t *testing.T) {
			name, description := "replacement", "replacement"
			if field == "name" {
				name = "a\x00b"
			} else {
				description = "a\x00b"
			}
			body := textRequestJSON(t, otherMD5, name, description)
			request(t, server, "POST", "/info", body, 400)
			request(t, server, "PUT", "/info/"+md5, body, 400)
			request(t, server, "GET", "/info/"+otherMD5, "", 404)
			assertThreat(t, request(t, server, "GET", "/info/"+md5, "", 200), want)
		})
	}
	// Literal backslash-u text, other controls, and empty strings remain valid.
	want.Name, want.Description = `literal \u0000`, "line\nnext\tcolumn\rreturn"
	assertThreat(t, request(t, server, "PUT", "/info/"+md5, textRequestJSON(t, md5, want.Name, want.Description), 200), want)
	want.Name, want.Description = "", ""
	assertThreat(t, request(t, server, "PUT", "/info/"+md5, textRequestJSON(t, md5, "", ""), 200), want)
}

func textRequestJSON(t *testing.T, md5, name, description string) string {
	t.Helper()
	data, err := json.Marshal(map[string]string{"md5": md5, "name": name, "description": description})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
