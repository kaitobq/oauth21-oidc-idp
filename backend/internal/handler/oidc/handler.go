package oidc

import (
	"encoding/json"
	"net/http"

	core "github.com/kaitobq/oauth21-oidc-idp/backend/internal/oidc"
)

type Handler struct {
	provider *core.Provider
}

func NewHandler(provider *core.Provider) *Handler {
	return &Handler{provider: provider}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/openid-configuration", h.discovery)
	mux.HandleFunc("/oauth2/jwks", h.jwks)
	mux.HandleFunc("/oauth2/authorize", h.notImplementedAuthorize)
	mux.HandleFunc("/oauth2/token", h.notImplementedToken)
}

func (h *Handler) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.provider.Discovery())
}

func (h *Handler) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.provider.JWKS())
}

func (h *Handler) notImplementedAuthorize(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error":             "temporarily_unavailable",
		"error_description": "authorization endpoint is not implemented yet",
	})
}

func (h *Handler) notImplementedToken(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error":             "temporarily_unavailable",
		"error_description": "token endpoint is not implemented yet",
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
