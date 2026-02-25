package oidc

import (
	"encoding/json"
	"errors"
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
	mux.HandleFunc("/oauth2/authorize", h.authorize)
	mux.HandleFunc("/oauth2/token", h.token)
}

func (h *Handler) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.provider.Discovery())
}

func (h *Handler) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.provider.JWKS())
}

func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{
			"error":             "invalid_request",
			"error_description": "method must be GET",
		})
		return
	}

	q := r.URL.Query()
	redirectURL, err := h.provider.Authorize(
		q.Get("response_type"),
		q.Get("client_id"),
		q.Get("redirect_uri"),
		q.Get("scope"),
		q.Get("state"),
		q.Get("code_challenge"),
		q.Get("code_challenge_method"),
	)
	if err != nil {
		h.writeOAuthError(w, err)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{
			"error":             "invalid_request",
			"error_description": "method must be POST",
		})
		return
	}

	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "failed to parse form payload",
		})
		return
	}

	resp, err := h.provider.ExchangeAuthorizationCode(
		r.PostForm.Get("grant_type"),
		r.PostForm.Get("code"),
		r.PostForm.Get("redirect_uri"),
		r.PostForm.Get("client_id"),
		r.PostForm.Get("code_verifier"),
	)
	if err != nil {
		h.writeOAuthError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) writeOAuthError(w http.ResponseWriter, err error) {
	var oauthErr *core.OAuthError
	if errors.As(err, &oauthErr) {
		writeJSON(w, oauthErr.Status, oauthErr.Response())
		return
	}

	writeJSON(w, http.StatusInternalServerError, map[string]string{
		"error":             "server_error",
		"error_description": "internal server error",
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
