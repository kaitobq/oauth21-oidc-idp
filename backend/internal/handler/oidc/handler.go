package oidc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/kaitobq/oauth21-oidc-idp/backend/internal/audit"
	"github.com/kaitobq/oauth21-oidc-idp/backend/internal/handler/middleware"
	core "github.com/kaitobq/oauth21-oidc-idp/backend/internal/oidc"
)

type Handler struct {
	provider                          *core.Provider
	auditLogger                       *audit.Logger
	enableSigningKeyRotation          bool
	signingKeyRotationToken           string
	enablePrivateJWTClientKeyRotation bool
	privateJWTClientKeyRotationToken  string
	adminAuthMode                     string
	adminJWTSecret                    string
	adminJWTIssuer                    string
	adminJWTAudience                  string
}

func newHandler(provider *core.Provider) *Handler {
	return &Handler{
		provider:      provider,
		auditLogger:   audit.New(),
		adminAuthMode: middleware.AdminAuthModeStatic,
	}
}

func NewHandler(provider *core.Provider) *Handler {
	return newHandler(provider)
}

func NewHandlerWithSigningKeyRotation(provider *core.Provider, rotationToken string) *Handler {
	return NewHandlerWithSigningKeyRotationAuth(provider, rotationToken, middleware.AdminAuthModeStatic, "", "", "")
}

func NewHandlerWithPrivateJWTClientKeyRotation(provider *core.Provider, rotationToken string) *Handler {
	return NewHandlerWithPrivateJWTClientKeyRotationAuth(provider, rotationToken, middleware.AdminAuthModeStatic, "", "", "")
}

func NewHandlerWithAdminAPIs(provider *core.Provider, signingKeyRotationToken, privateJWTClientKeyRotationToken string) *Handler {
	return NewHandlerWithAdminAPIsAuth(
		provider,
		signingKeyRotationToken,
		privateJWTClientKeyRotationToken,
		middleware.AdminAuthModeStatic,
		"",
		"",
		"",
	)
}

func NewHandlerWithSigningKeyRotationAuth(
	provider *core.Provider,
	rotationToken, adminAuthMode, adminJWTSecret, adminJWTIssuer, adminJWTAudience string,
) *Handler {
	h := newHandler(provider)
	h.enableSigningKeyRotation = true
	h.signingKeyRotationToken = strings.TrimSpace(rotationToken)
	h.adminAuthMode = strings.TrimSpace(adminAuthMode)
	h.adminJWTSecret = strings.TrimSpace(adminJWTSecret)
	h.adminJWTIssuer = strings.TrimSpace(adminJWTIssuer)
	h.adminJWTAudience = strings.TrimSpace(adminJWTAudience)
	return h
}

func NewHandlerWithPrivateJWTClientKeyRotationAuth(
	provider *core.Provider,
	rotationToken, adminAuthMode, adminJWTSecret, adminJWTIssuer, adminJWTAudience string,
) *Handler {
	h := newHandler(provider)
	h.enablePrivateJWTClientKeyRotation = true
	h.privateJWTClientKeyRotationToken = strings.TrimSpace(rotationToken)
	h.adminAuthMode = strings.TrimSpace(adminAuthMode)
	h.adminJWTSecret = strings.TrimSpace(adminJWTSecret)
	h.adminJWTIssuer = strings.TrimSpace(adminJWTIssuer)
	h.adminJWTAudience = strings.TrimSpace(adminJWTAudience)
	return h
}

func NewHandlerWithAdminAPIsAuth(
	provider *core.Provider,
	signingKeyRotationToken, privateJWTClientKeyRotationToken string,
	adminAuthMode, adminJWTSecret, adminJWTIssuer, adminJWTAudience string,
) *Handler {
	h := newHandler(provider)
	h.enableSigningKeyRotation = true
	h.signingKeyRotationToken = strings.TrimSpace(signingKeyRotationToken)
	h.enablePrivateJWTClientKeyRotation = true
	h.privateJWTClientKeyRotationToken = strings.TrimSpace(privateJWTClientKeyRotationToken)
	h.adminAuthMode = strings.TrimSpace(adminAuthMode)
	h.adminJWTSecret = strings.TrimSpace(adminJWTSecret)
	h.adminJWTIssuer = strings.TrimSpace(adminJWTIssuer)
	h.adminJWTAudience = strings.TrimSpace(adminJWTAudience)
	return h
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/openid-configuration", h.discovery)
	mux.HandleFunc("/oauth2/jwks", h.jwks)
	mux.HandleFunc("/oauth2/authorize", h.authorize)
	mux.HandleFunc("/oauth2/token", h.token)
	mux.HandleFunc("/oauth2/userinfo", h.userInfo)
	if h.enableSigningKeyRotation {
		mux.Handle(
			"/oauth2/admin/rotate-signing-key",
			middleware.AdminAuth(middleware.AdminAuthConfig{
				Mode:        h.adminAuthMode,
				StaticToken: h.signingKeyRotationToken,
				JWTSecret:   h.adminJWTSecret,
				JWTIssuer:   h.adminJWTIssuer,
				JWTAudience: h.adminJWTAudience,
				Methods:     []string{http.MethodPost},
			}, middleware.ScopeRotateSigningKey)(http.HandlerFunc(h.rotateSigningKey)),
		)
	}
	if h.enablePrivateJWTClientKeyRotation {
		mux.Handle(
			"/oauth2/admin/rotate-private-jwt-client-key",
			middleware.AdminAuth(middleware.AdminAuthConfig{
				Mode:        h.adminAuthMode,
				StaticToken: h.privateJWTClientKeyRotationToken,
				JWTSecret:   h.adminJWTSecret,
				JWTIssuer:   h.adminJWTIssuer,
				JWTAudience: h.adminJWTAudience,
				Methods:     []string{http.MethodPost},
			}, middleware.ScopeRotatePrivateJWTClientKey)(http.HandlerFunc(h.rotatePrivateJWTClientKey)),
		)
	}
}

func (h *Handler) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.provider.Discovery())
}

func (h *Handler) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.provider.JWKS())
}

func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	clientID := strings.TrimSpace(r.URL.Query().Get("client_id"))

	if r.Method != http.MethodGet {
		h.audit("oidc.authorize", map[string]any{
			"result":    "reject",
			"reason":    "method_not_allowed",
			"method":    r.Method,
			"path":      r.URL.Path,
			"client_id": clientID,
		})
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
		h.audit("oidc.authorize", map[string]any{
			"result":      "error",
			"client_id":   clientID,
			"oauth_error": oauthErrorCode(err),
		})
		h.writeOAuthError(w, err)
		return
	}

	h.audit("oidc.authorize", map[string]any{
		"result":    "success",
		"client_id": clientID,
	})
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.audit("oidc.token", map[string]any{
			"result": "reject",
			"reason": "method_not_allowed",
			"method": r.Method,
			"path":   r.URL.Path,
		})
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{
			"error":             "invalid_request",
			"error_description": "method must be POST",
		})
		return
	}

	if err := r.ParseForm(); err != nil {
		h.audit("oidc.token", map[string]any{
			"result":      "error",
			"oauth_error": "invalid_request",
			"reason":      "parse_form_failed",
		})
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "failed to parse form payload",
		})
		return
	}

	grantType := r.PostForm.Get("grant_type")
	formClientID := strings.TrimSpace(r.PostForm.Get("client_id"))
	clientAuth, err := resolveTokenClientAuthentication(r)
	if err != nil {
		h.audit("oidc.token", map[string]any{
			"result":      "error",
			"grant_type":  grantType,
			"client_id":   formClientID,
			"oauth_error": oauthErrorCode(err),
		})
		h.writeOAuthError(w, err)
		return
	}
	if err := h.provider.AuthenticateTokenClient(clientAuth); err != nil {
		h.audit("oidc.token", map[string]any{
			"result":      "error",
			"grant_type":  grantType,
			"client_id":   clientAuth.ClientID,
			"auth_method": clientAuth.AuthMethod,
			"oauth_error": oauthErrorCode(err),
		})
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
		h.audit("oidc.token", map[string]any{
			"result":      "error",
			"grant_type":  grantType,
			"client_id":   clientAuth.ClientID,
			"auth_method": clientAuth.AuthMethod,
			"oauth_error": oauthErrorCode(exchangeErr),
		})
		h.writeOAuthError(w, exchangeErr)
		return
	}

	h.audit("oidc.token", map[string]any{
		"result":      "success",
		"grant_type":  grantType,
		"client_id":   clientAuth.ClientID,
		"auth_method": clientAuth.AuthMethod,
	})
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) userInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		h.audit("oidc.userinfo", map[string]any{
			"result": "reject",
			"reason": "method_not_allowed",
			"method": r.Method,
			"path":   r.URL.Path,
		})
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{
			"error":             "invalid_request",
			"error_description": "method must be GET or POST",
		})
		return
	}

	accessToken, err := resolveBearerToken(r.Header.Get("Authorization"))
	if err != nil {
		h.audit("oidc.userinfo", map[string]any{
			"result":      "error",
			"oauth_error": oauthErrorCode(err),
		})
		h.writeBearerOAuthError(w, err)
		return
	}

	resp, err := h.provider.UserInfo(accessToken)
	if err != nil {
		h.audit("oidc.userinfo", map[string]any{
			"result":      "error",
			"oauth_error": oauthErrorCode(err),
		})
		h.writeBearerOAuthError(w, err)
		return
	}

	h.audit("oidc.userinfo", map[string]any{
		"result": "success",
	})
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) rotateSigningKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.audit("oidc.admin.rotate_signing_key", map[string]any{
			"result": "reject",
			"reason": "method_not_allowed",
			"method": r.Method,
		})
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{
			"error":             "invalid_request",
			"error_description": "method must be POST",
		})
		return
	}

	kid, err := h.provider.RotateSigningKey()
	if err != nil {
		h.audit("oidc.admin.rotate_signing_key", map[string]any{
			"result": "error",
			"reason": "rotate_failed",
		})
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "failed to rotate signing key",
		})
		return
	}
	h.audit("oidc.admin.rotate_signing_key", map[string]any{
		"result": "success",
		"kid":    kid,
	})
	writeJSON(w, http.StatusOK, map[string]string{"kid": kid})
}

func (h *Handler) rotatePrivateJWTClientKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.audit("oidc.admin.rotate_private_jwt_client_key", map[string]any{
			"result": "reject",
			"reason": "method_not_allowed",
			"method": r.Method,
		})
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{
			"error":             "invalid_request",
			"error_description": "method must be POST",
		})
		return
	}

	var payload struct {
		ClientID     string `json:"client_id"`
		PublicKeyPEM string `json:"public_key_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.audit("oidc.admin.rotate_private_jwt_client_key", map[string]any{
			"result": "error",
			"reason": "invalid_json",
		})
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "request body must be valid json",
		})
		return
	}
	payload.ClientID = strings.TrimSpace(payload.ClientID)
	payload.PublicKeyPEM = strings.TrimSpace(payload.PublicKeyPEM)
	if payload.ClientID == "" || payload.PublicKeyPEM == "" {
		h.audit("oidc.admin.rotate_private_jwt_client_key", map[string]any{
			"result": "error",
			"reason": "missing_required_fields",
		})
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "client_id and public_key_pem are required",
		})
		return
	}

	kid, err := h.provider.RotatePrivateJWTClientKey(payload.ClientID, payload.PublicKeyPEM)
	if err != nil {
		h.audit("oidc.admin.rotate_private_jwt_client_key", map[string]any{
			"result":    "error",
			"reason":    "rotate_failed",
			"client_id": payload.ClientID,
		})
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "failed to rotate private_key_jwt client key",
		})
		return
	}
	h.audit("oidc.admin.rotate_private_jwt_client_key", map[string]any{
		"result":    "success",
		"client_id": payload.ClientID,
		"kid":       kid,
	})
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

func (h *Handler) writeBearerOAuthError(w http.ResponseWriter, err error) {
	var oauthErr *core.OAuthError
	if errors.As(err, &oauthErr) {
		if oauthErr.Code == "invalid_token" || oauthErr.Code == "insufficient_scope" {
			w.Header().Set("WWW-Authenticate", bearerWWWAuthenticateHeader(oauthErr.Code, oauthErr.Description))
		}
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

func (h *Handler) audit(event string, fields map[string]any) {
	if h.auditLogger == nil {
		return
	}
	h.auditLogger.Log(event, fields)
}

func oauthErrorCode(err error) string {
	var oauthErr *core.OAuthError
	if errors.As(err, &oauthErr) {
		return oauthErr.Code
	}
	return "server_error"
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

func resolveBearerToken(authorization string) (string, error) {
	authorization = strings.TrimSpace(authorization)
	if authorization == "" {
		return "", &core.OAuthError{
			Code:        "invalid_token",
			Description: "authorization header must use bearer token",
			Status:      http.StatusUnauthorized,
		}
	}

	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", &core.OAuthError{
			Code:        "invalid_token",
			Description: "authorization header must use bearer token",
			Status:      http.StatusUnauthorized,
		}
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", &core.OAuthError{
			Code:        "invalid_token",
			Description: "bearer token must not be empty",
			Status:      http.StatusUnauthorized,
		}
	}
	return token, nil
}

func bearerWWWAuthenticateHeader(code, description string) string {
	code = strings.TrimSpace(code)
	description = strings.TrimSpace(description)

	header := `Bearer realm="oauth2/userinfo"`
	if code != "" {
		header += `, error="` + strings.ReplaceAll(code, `"`, `'`) + `"`
	}
	if description != "" {
		header += `, error_description="` + strings.ReplaceAll(description, `"`, `'`) + `"`
	}
	return header
}
