package httptransport

import (
	"fmt"
	"net/http"
)

func (h *handler) recoverErrors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				h.writeError(w, fmt.Errorf("panic in HTTP handler: %v", err))
			}
		}()
		next.ServeHTTP(w, r)
	})
}
