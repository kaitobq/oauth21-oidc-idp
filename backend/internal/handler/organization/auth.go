package organization

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	app "github.com/kaitobq/oauth21-oidc-idp/backend/internal/application/organization"
	"github.com/kaitobq/oauth21-oidc-idp/backend/internal/infra/authz"
)

const (
	OrganizationAuthModeHeader = "header"
	OrganizationAuthModeStatic = "static"
	OrganizationAuthModeJWT    = "jwt"
)

type AuthConfig struct {
	Mode        string
	StaticToken string
	JWTSecret   string
	JWTIssuer   string
	JWTAudience string
}

type actorResolver struct {
	cfg AuthConfig
}

func newActorResolver(cfg AuthConfig) *actorResolver {
	mode := strings.TrimSpace(strings.ToLower(cfg.Mode))
	if mode == "" {
		mode = OrganizationAuthModeStatic
	}
	cfg.Mode = mode
	cfg.StaticToken = strings.TrimSpace(cfg.StaticToken)
	cfg.JWTSecret = strings.TrimSpace(cfg.JWTSecret)
	cfg.JWTIssuer = strings.TrimSpace(cfg.JWTIssuer)
	cfg.JWTAudience = strings.TrimSpace(cfg.JWTAudience)
	if cfg.JWTAudience == "" {
		cfg.JWTAudience = "organization-api"
	}
	return &actorResolver{cfg: cfg}
}

func (r *actorResolver) Resolve(header http.Header) (*app.Actor, error) {
	if r == nil {
		return nil, app.ErrUnauthenticated
	}

	switch r.cfg.Mode {
	case OrganizationAuthModeHeader:
		return actorFromHeaderValues(header), nil
	case OrganizationAuthModeStatic:
		token, err := bearerTokenFromAuthorization(header.Get("Authorization"))
		if err != nil {
			return nil, err
		}
		if r.cfg.StaticToken == "" {
			return nil, fmt.Errorf("%w: static token is not configured", app.ErrUnauthenticated)
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(r.cfg.StaticToken)) != 1 {
			return nil, fmt.Errorf("%w: invalid static token", app.ErrUnauthenticated)
		}
		return app.NewActor("organization-static-admin", []string{authz.ScopeOrganizationAdmin}), nil
	case OrganizationAuthModeJWT:
		token, err := bearerTokenFromAuthorization(header.Get("Authorization"))
		if err != nil {
			return nil, err
		}
		return r.resolveJWTActor(token)
	default:
		return nil, fmt.Errorf("%w: unsupported organization auth mode %q", app.ErrUnauthenticated, r.cfg.Mode)
	}
}

func bearerTokenFromAuthorization(authorization string) (string, error) {
	authorization = strings.TrimSpace(authorization)
	if authorization == "" {
		return "", fmt.Errorf("%w: authorization header must use bearer token", app.ErrUnauthenticated)
	}

	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", fmt.Errorf("%w: authorization header must use bearer token", app.ErrUnauthenticated)
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", fmt.Errorf("%w: bearer token must not be empty", app.ErrUnauthenticated)
	}
	return token, nil
}

func (r *actorResolver) resolveJWTActor(token string) (*app.Actor, error) {
	if r.cfg.JWTSecret == "" {
		return nil, fmt.Errorf("%w: jwt secret is not configured", app.ErrUnauthenticated)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: jwt format is invalid", app.ErrUnauthenticated)
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: jwt header encoding is invalid", app.ErrUnauthenticated)
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: jwt claims encoding is invalid", app.ErrUnauthenticated)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: jwt signature encoding is invalid", app.ErrUnauthenticated)
	}

	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("%w: jwt header is invalid", app.ErrUnauthenticated)
	}
	if !strings.EqualFold(strings.TrimSpace(header.Alg), "HS256") {
		return nil, fmt.Errorf("%w: jwt alg must be HS256", app.ErrUnauthenticated)
	}

	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(r.cfg.JWTSecret))
	_, _ = mac.Write([]byte(signingInput))
	expectedSignature := mac.Sum(nil)
	if subtle.ConstantTimeCompare(signature, expectedSignature) != 1 {
		return nil, fmt.Errorf("%w: jwt signature verification failed", app.ErrUnauthenticated)
	}

	var claims map[string]any
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("%w: jwt claims are invalid", app.ErrUnauthenticated)
	}

	now := time.Now().UTC().Unix()
	exp, ok := numericClaim(claims["exp"])
	if !ok || now >= exp {
		return nil, fmt.Errorf("%w: jwt has expired", app.ErrUnauthenticated)
	}
	if nbf, ok := numericClaim(claims["nbf"]); ok && now < nbf {
		return nil, fmt.Errorf("%w: jwt is not yet valid", app.ErrUnauthenticated)
	}
	if iat, ok := numericClaim(claims["iat"]); ok && iat > now+60 {
		return nil, fmt.Errorf("%w: jwt iat is in the future", app.ErrUnauthenticated)
	}
	if r.cfg.JWTIssuer != "" {
		iss, ok := claims["iss"].(string)
		if !ok || strings.TrimSpace(iss) != r.cfg.JWTIssuer {
			return nil, fmt.Errorf("%w: jwt iss is invalid", app.ErrUnauthenticated)
		}
	}
	if r.cfg.JWTAudience != "" && !audienceClaimContains(claims["aud"], r.cfg.JWTAudience) {
		return nil, fmt.Errorf("%w: jwt aud is invalid", app.ErrUnauthenticated)
	}

	sub, ok := claims["sub"].(string)
	if !ok || strings.TrimSpace(sub) == "" {
		return nil, fmt.Errorf("%w: jwt sub is required", app.ErrUnauthenticated)
	}
	scopes := extractScopes(claims)
	return app.NewActor(sub, scopes), nil
}

func actorFromHeaderValues(header http.Header) *app.Actor {
	sub := strings.TrimSpace(header.Get("x-actor-sub"))
	scopeValue := strings.TrimSpace(header.Get("x-actor-scopes"))
	if scopeValue == "" {
		scopeValue = strings.TrimSpace(header.Get("x-actor-scope"))
	}

	scopes := []string{}
	if scopeValue != "" {
		scopes = strings.Fields(scopeValue)
	}
	return app.NewActor(sub, scopes)
}

func numericClaim(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return i, true
	default:
		return 0, false
	}
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

func extractScopes(claims map[string]any) []string {
	scopeSet := map[string]struct{}{}
	if rawScope, ok := claims["scope"].(string); ok {
		for _, scope := range strings.Fields(rawScope) {
			scopeSet[scope] = struct{}{}
		}
	}
	switch rawSCP := claims["scp"].(type) {
	case string:
		for _, scope := range strings.Fields(rawSCP) {
			scopeSet[scope] = struct{}{}
		}
	case []any:
		for _, scope := range rawSCP {
			if s, ok := scope.(string); ok && strings.TrimSpace(s) != "" {
				scopeSet[strings.TrimSpace(s)] = struct{}{}
			}
		}
	}

	out := make([]string, 0, len(scopeSet))
	for scope := range scopeSet {
		out = append(out, scope)
	}
	return out
}
