package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	AdminAuthModeStatic = "static"
	AdminAuthModeJWT    = "jwt"

	ScopeRotateSigningKey          = "oidc.admin.rotate_signing_key"
	ScopeRotatePrivateJWTClientKey = "oidc.admin.rotate_private_jwt_client_key"
)

type AdminAuthConfig struct {
	Mode        string
	StaticToken string
	JWTSecret   string
	JWTIssuer   string
	JWTAudience string
	Methods     []string
}

type authError struct {
	Status      int
	Code        string
	Description string
	BearerError string
}

var adminJWTReplayGuard = struct {
	mu      sync.Mutex
	entries map[string]int64
}{
	entries: map[string]int64{},
}

// Auth keeps backward compatibility. Use AdminAuth for validated bearer authentication.
func Auth(next http.Handler) http.Handler {
	return next
}

// AdminAuth validates bearer tokens for admin endpoints.
// mode=static: validates against StaticToken
// mode=jwt: validates HS256 JWT claims and required scope
func AdminAuth(cfg AdminAuthConfig, requiredScope string) func(http.Handler) http.Handler {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = AdminAuthModeStatic
	}
	allowedMethods := map[string]struct{}{}
	for _, method := range cfg.Methods {
		m := strings.ToUpper(strings.TrimSpace(method))
		if m == "" {
			continue
		}
		allowedMethods[m] = struct{}{}
	}
	requiredScope = strings.TrimSpace(requiredScope)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(allowedMethods) > 0 {
				if _, ok := allowedMethods[strings.ToUpper(r.Method)]; !ok {
					next.ServeHTTP(w, r)
					return
				}
			}

			token, err := bearerTokenFromAuthorization(r.Header.Get("Authorization"))
			if err != nil {
				writeAuthError(w, err)
				return
			}

			switch mode {
			case AdminAuthModeStatic:
				if authErr := validateStaticToken(token, cfg.StaticToken); authErr != nil {
					writeAuthError(w, authErr)
					return
				}
			case AdminAuthModeJWT:
				if authErr := validateJWTToken(token, cfg.JWTSecret, cfg.JWTIssuer, cfg.JWTAudience, requiredScope); authErr != nil {
					writeAuthError(w, authErr)
					return
				}
			default:
				writeAuthError(w, &authError{
					Status:      http.StatusInternalServerError,
					Code:        "server_error",
					Description: "unsupported admin auth mode",
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func bearerTokenFromAuthorization(authorization string) (string, *authError) {
	authorization = strings.TrimSpace(authorization)
	if authorization == "" {
		return "", &authError{
			Status:      http.StatusUnauthorized,
			Code:        "unauthorized",
			Description: "authorization header must use bearer token",
			BearerError: "invalid_token",
		}
	}

	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", &authError{
			Status:      http.StatusUnauthorized,
			Code:        "unauthorized",
			Description: "authorization header must use bearer token",
			BearerError: "invalid_token",
		}
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", &authError{
			Status:      http.StatusUnauthorized,
			Code:        "unauthorized",
			Description: "bearer token must not be empty",
			BearerError: "invalid_token",
		}
	}
	return token, nil
}

func validateStaticToken(token, configuredToken string) *authError {
	configuredToken = strings.TrimSpace(configuredToken)
	if configuredToken == "" {
		return &authError{
			Status:      http.StatusInternalServerError,
			Code:        "server_error",
			Description: "admin bearer token is not configured",
		}
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(token)), []byte(configuredToken)) != 1 {
		return &authError{
			Status:      http.StatusUnauthorized,
			Code:        "unauthorized",
			Description: "invalid admin bearer token",
			BearerError: "invalid_token",
		}
	}
	return nil
}

func validateJWTToken(token, secret, issuer, audience, requiredScope string) *authError {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return &authError{
			Status:      http.StatusInternalServerError,
			Code:        "server_error",
			Description: "admin jwt secret is not configured",
		}
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return &authError{
			Status:      http.StatusUnauthorized,
			Code:        "unauthorized",
			Description: "admin jwt format is invalid",
			BearerError: "invalid_token",
		}
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return &authError{
			Status:      http.StatusUnauthorized,
			Code:        "unauthorized",
			Description: "admin jwt header encoding is invalid",
			BearerError: "invalid_token",
		}
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return &authError{
			Status:      http.StatusUnauthorized,
			Code:        "unauthorized",
			Description: "admin jwt claims encoding is invalid",
			BearerError: "invalid_token",
		}
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return &authError{
			Status:      http.StatusUnauthorized,
			Code:        "unauthorized",
			Description: "admin jwt signature encoding is invalid",
			BearerError: "invalid_token",
		}
	}

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ,omitempty"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return &authError{
			Status:      http.StatusUnauthorized,
			Code:        "unauthorized",
			Description: "admin jwt header is invalid",
			BearerError: "invalid_token",
		}
	}
	if !strings.EqualFold(strings.TrimSpace(header.Alg), "HS256") {
		return &authError{
			Status:      http.StatusUnauthorized,
			Code:        "unauthorized",
			Description: "admin jwt alg must be HS256",
			BearerError: "invalid_token",
		}
	}

	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signingInput))
	expectedSignature := mac.Sum(nil)
	if subtle.ConstantTimeCompare(signature, expectedSignature) != 1 {
		return &authError{
			Status:      http.StatusUnauthorized,
			Code:        "unauthorized",
			Description: "admin jwt signature verification failed",
			BearerError: "invalid_token",
		}
	}

	var claims map[string]any
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return &authError{
			Status:      http.StatusUnauthorized,
			Code:        "unauthorized",
			Description: "admin jwt claims are invalid",
			BearerError: "invalid_token",
		}
	}

	now := time.Now().UTC().Unix()
	exp, ok := numericClaim(claims["exp"])
	if !ok || now >= exp {
		return &authError{
			Status:      http.StatusUnauthorized,
			Code:        "unauthorized",
			Description: "admin jwt has expired",
			BearerError: "invalid_token",
		}
	}
	if nbf, ok := numericClaim(claims["nbf"]); ok && now < nbf {
		return &authError{
			Status:      http.StatusUnauthorized,
			Code:        "unauthorized",
			Description: "admin jwt is not yet valid",
			BearerError: "invalid_token",
		}
	}
	if iat, ok := numericClaim(claims["iat"]); ok && iat > now+60 {
		return &authError{
			Status:      http.StatusUnauthorized,
			Code:        "unauthorized",
			Description: "admin jwt iat is in the future",
			BearerError: "invalid_token",
		}
	}
	jti, ok := claims["jti"].(string)
	jti = strings.TrimSpace(jti)
	if !ok || jti == "" {
		return &authError{
			Status:      http.StatusUnauthorized,
			Code:        "unauthorized",
			Description: "admin jwt jti is required",
			BearerError: "invalid_token",
		}
	}

	issuer = strings.TrimSpace(issuer)
	if issuer != "" {
		iss, ok := claims["iss"].(string)
		if !ok || strings.TrimSpace(iss) != issuer {
			return &authError{
				Status:      http.StatusUnauthorized,
				Code:        "unauthorized",
				Description: "admin jwt iss is invalid",
				BearerError: "invalid_token",
			}
		}
	}

	audience = strings.TrimSpace(audience)
	if audience != "" && !audienceClaimContains(claims["aud"], audience) {
		return &authError{
			Status:      http.StatusUnauthorized,
			Code:        "unauthorized",
			Description: "admin jwt aud is invalid",
			BearerError: "invalid_token",
		}
	}

	requiredScope = strings.TrimSpace(requiredScope)
	if requiredScope != "" && !scopeContains(claims, requiredScope) {
		return &authError{
			Status:      http.StatusForbidden,
			Code:        "forbidden",
			Description: "admin jwt scope is insufficient",
			BearerError: "insufficient_scope",
		}
	}
	if adminJWTReplayDetected(claims, jti, exp, now) {
		return &authError{
			Status:      http.StatusUnauthorized,
			Code:        "unauthorized",
			Description: "admin jwt has been replayed",
			BearerError: "invalid_token",
		}
	}

	return nil
}

func numericClaim(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	}
	return 0, false
}

func audienceClaimContains(v any, expected string) bool {
	switch aud := v.(type) {
	case string:
		return strings.TrimSpace(aud) == expected
	case []any:
		for _, candidate := range aud {
			if s, ok := candidate.(string); ok && strings.TrimSpace(s) == expected {
				return true
			}
		}
	}
	return false
}

func scopeContains(claims map[string]any, target string) bool {
	if target == "" {
		return true
	}
	if rawScope, ok := claims["scope"].(string); ok {
		for _, scope := range strings.Fields(rawScope) {
			if scope == target {
				return true
			}
		}
	}
	switch rawSCP := claims["scp"].(type) {
	case string:
		for _, scope := range strings.Fields(rawSCP) {
			if scope == target {
				return true
			}
		}
	case []any:
		for _, scope := range rawSCP {
			if s, ok := scope.(string); ok && s == target {
				return true
			}
		}
	}
	return false
}

func adminJWTReplayDetected(claims map[string]any, jti string, exp, now int64) bool {
	adminJWTReplayGuard.mu.Lock()
	defer adminJWTReplayGuard.mu.Unlock()

	for key, expiresAt := range adminJWTReplayGuard.entries {
		if expiresAt <= now {
			delete(adminJWTReplayGuard.entries, key)
		}
	}

	cacheKey := strings.Join([]string{
		claimString(claims, "iss"),
		audienceCacheKey(claims["aud"]),
		jti,
	}, "|")
	if _, exists := adminJWTReplayGuard.entries[cacheKey]; exists {
		return true
	}
	adminJWTReplayGuard.entries[cacheKey] = exp
	return false
}

func claimString(claims map[string]any, key string) string {
	if claims == nil {
		return ""
	}
	v, ok := claims[key].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(v)
}

func audienceCacheKey(v any) string {
	switch aud := v.(type) {
	case string:
		return strings.TrimSpace(aud)
	case []any:
		values := make([]string, 0, len(aud))
		for _, candidate := range aud {
			if s, ok := candidate.(string); ok && strings.TrimSpace(s) != "" {
				values = append(values, strings.TrimSpace(s))
			}
		}
		sort.Strings(values)
		return strings.Join(values, ",")
	default:
		return ""
	}
}

func writeAuthError(w http.ResponseWriter, err *authError) {
	if err == nil {
		return
	}

	if err.BearerError != "" {
		w.Header().Set("WWW-Authenticate", bearerAuthenticateHeader(err.BearerError, err.Description))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.Status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             err.Code,
		"error_description": err.Description,
	})
}

func bearerAuthenticateHeader(code, description string) string {
	header := `Bearer realm="oidc/admin"`
	code = strings.TrimSpace(code)
	description = strings.TrimSpace(description)
	if code != "" {
		header += `, error="` + strings.ReplaceAll(code, `"`, `'`) + `"`
	}
	if description != "" {
		header += `, error_description="` + strings.ReplaceAll(description, `"`, `'`) + `"`
	}
	return header
}
