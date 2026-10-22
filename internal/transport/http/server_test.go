package httptransport

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"
)

func TestNewServerTimeouts(t *testing.T) {
	handler := http.NewServeMux()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	server := NewServer(":8443", handler, tlsConfig)
	if server.Addr != ":8443" || server.Handler != handler || server.TLSConfig != tlsConfig {
		t.Fatal("server lost its address, handler, or TLS configuration")
	}
	for _, test := range []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"headers", server.ReadHeaderTimeout, 3 * time.Second},
		{"request", server.ReadTimeout, 5 * time.Second},
		{"response", server.WriteTimeout, 10 * time.Second},
		{"idle connection", server.IdleTimeout, 60 * time.Second},
	} {
		if test.got != test.want {
			t.Errorf("%s timeout = %s, want %s", test.name, test.got, test.want)
		}
	}
}
