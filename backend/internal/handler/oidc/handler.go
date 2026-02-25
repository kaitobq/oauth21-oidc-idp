package oidc

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	core "github.com/kaitobq/oauth21-oidc-idp/backend/internal/oidc"
)

type Handler struct {
	provider                 *core.Provider
	enableSigningKeyRotation bool
	signingKeyRotationToken  string
}

func NewHandler(provider *core.Provider) *Handler {
	return &Handler{provider: provider}
}

func NewHandlerWithSigningKeyRotation(provider *core.Provider, rotationToken string) *Handler {
	return &Handler{
		provider:                 provider,
		enableSigningKeyRotation: true,
		signingKeyRotationToken:  strings.TrimSpace(rotationToken),
	}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/openid-configuration", h.discovery)
	mux.HandleFunc("/oauth2/jwks", h.jwks)
	mux.HandleFunc("/oauth2/authorize", h.authorize)
	mux.HandleFunc("/oauth2/token", h.token)
	if h.enableSigningKeyRotation {
		mux.HandleFunc("/oauth2/admin/rotate-signing-key", h.rotateSigningKey)
	}
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
		q.Get("nonce"),
		q.Get("acr_values"),
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

	grantType := r.PostForm.Get("grant_type")
	clientAuth, err := resolveTokenClientAuthentication(r)
	if err != nil {
		h.writeOAuthError(w, err)
		return
	}
	if err := h.provider.AuthenticateTokenClient(clientAuth); err != nil {
		h.writeOAuthError(w, err)
		return
	}

	var (
		resp        *core.TokenResponse
		exchangeErr error
	)
	switch grantType {
	case "authorization_code":
		resp, exchangeErr = h.provider.ExchangeAuthorizationCode(
			grantType,
			r.PostForm.Get("code"),
			r.PostForm.Get("redirect_uri"),
			clientAuth.ClientID,
			r.PostForm.Get("code_verifier"),
		)
	case "refresh_token":
		resp, exchangeErr = h.provider.ExchangeRefreshToken(
			grantType,
			r.PostForm.Get("refresh_token"),
			clientAuth.ClientID,
			r.PostForm.Get("scope"),
		)
	default:
		exchangeErr = &core.OAuthError{Code: "unsupported_grant_type", Description: "unsupported grant_type", Status: http.StatusBadRequest}
	}
	if exchangeErr != nil {
		h.writeOAuthError(w, exchangeErr)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) rotateSigningKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{
			"error":             "invalid_request",
			"error_description": "method must be POST",
		})
		return
	}

	if strings.TrimSpace(h.signingKeyRotationToken) == "" {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "signing key rotation token is not configured",
		})
		return
	}

	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error":             "unauthorized",
			"error_description": "authorization header must use bearer token",
		})
		return
	}
	token := strings.TrimSpace(parts[1])
	if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(h.signingKeyRotationToken)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error":             "unauthorized",
			"error_description": "invalid signing key rotation token",
		})
		return
	}

	kid, err := h.provider.RotateSigningKey()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "failed to rotate signing key",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"kid": kid})
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

func resolveTokenClientAuthentication(r *http.Request) (core.TokenClientAuthentication, error) {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	formClientID := strings.TrimSpace(r.PostForm.Get("client_id"))
	formClientSecret := r.PostForm.Get("client_secret")
	formClientAssertionType := strings.TrimSpace(r.PostForm.Get("client_assertion_type"))
	formClientAssertion := strings.TrimSpace(r.PostForm.Get("client_assertion"))

	if authorization == "" {
		if formClientAssertionType != "" || formClientAssertion != "" {
			if formClientSecret != "" {
				return core.TokenClientAuthentication{}, &core.OAuthError{
					Code:        "invalid_client",
					Description: "multiple client authentication methods are not allowed",
					Status:      http.StatusUnauthorized,
				}
			}
			return core.TokenClientAuthentication{
				ClientID:            formClientID,
				AuthMethod:          core.TokenEndpointAuthMethodPrivate,
				ClientAssertionType: formClientAssertionType,
				ClientAssertion:     formClientAssertion,
			}, nil
		}
		if formClientSecret != "" {
			return core.TokenClientAuthentication{}, &core.OAuthError{
				Code:        "invalid_client",
				Description: "client_secret_post is not supported",
				Status:      http.StatusUnauthorized,
			}
		}
		return core.TokenClientAuthentication{
			ClientID:   formClientID,
			AuthMethod: core.TokenEndpointAuthMethodNone,
		}, nil
	}

	if formClientAssertionType != "" || formClientAssertion != "" || formClientSecret != "" {
		return core.TokenClientAuthentication{}, &core.OAuthError{
			Code:        "invalid_client",
			Description: "multiple client authentication methods are not allowed",
			Status:      http.StatusUnauthorized,
		}
	}

	authorizationParts := strings.SplitN(authorization, " ", 2)
	if len(authorizationParts) != 2 || !strings.EqualFold(authorizationParts[0], "Basic") {
		return core.TokenClientAuthentication{}, &core.OAuthError{
			Code:        "invalid_client",
			Description: "authorization header must use basic scheme",
			Status:      http.StatusUnauthorized,
		}
	}

	encodedCredentials := strings.TrimSpace(authorizationParts[1])
	if encodedCredentials == "" {
		return core.TokenClientAuthentication{}, &core.OAuthError{
			Code:        "invalid_client",
			Description: "missing basic credentials",
			Status:      http.StatusUnauthorized,
		}
	}

	rawCredentials, decodeErr := base64.StdEncoding.DecodeString(encodedCredentials)
	if decodeErr != nil {
		return core.TokenClientAuthentication{}, &core.OAuthError{
			Code:        "invalid_client",
			Description: "invalid basic credentials encoding",
			Status:      http.StatusUnauthorized,
		}
	}

	credentials := string(rawCredentials)
	separator := strings.IndexByte(credentials, ':')
	if separator <= 0 {
		return core.TokenClientAuthentication{}, &core.OAuthError{
			Code:        "invalid_client",
			Description: "invalid basic credentials format",
			Status:      http.StatusUnauthorized,
		}
	}

	clientID := credentials[:separator]
	clientSecret := credentials[separator+1:]
	if formClientID != "" && formClientID != clientID {
		return core.TokenClientAuthentication{}, &core.OAuthError{
			Code:        "invalid_client",
			Description: "client_id in body does not match authorization header",
			Status:      http.StatusUnauthorized,
		}
	}

	return core.TokenClientAuthentication{
		ClientID:     clientID,
		AuthMethod:   core.TokenEndpointAuthMethodBasic,
		ClientSecret: clientSecret,
	}, nil
}
