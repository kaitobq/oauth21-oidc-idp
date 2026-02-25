package middleware

import "net/http"

// Auth returns middleware that validates authentication.
// TODO: Implement JWT / session validation for OAuth 2.1 flows.
func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: Extract and validate bearer token
		next.ServeHTTP(w, r)
	})
}
