package organization

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	app "github.com/kaitobq/oauth21-oidc-idp/backend/internal/application/organization"
	"github.com/kaitobq/oauth21-oidc-idp/backend/internal/infra/authz"
)

func TestActorResolverHeaderMode(t *testing.T) {
	t.Parallel()

	resolver := newActorResolver(AuthConfig{Mode: OrganizationAuthModeHeader})
	header := http.Header{}
	header.Set("x-actor-sub", "alice")
	header.Set("x-actor-scopes", "organization.read organization.write")

	actor, err := resolver.Resolve(header)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if actor.Subject != "alice" {
		t.Fatalf("subject mismatch: got=%s want=alice", actor.Subject)
	}
	if !actor.HasScope(authz.ScopeOrganizationRead) {
		t.Fatalf("actor must have organization.read scope")
	}
	if !actor.HasScope(authz.ScopeOrganizationWrite) {
		t.Fatalf("actor must have organization.write scope")
	}
}

func TestActorResolverStaticMode(t *testing.T) {
	t.Parallel()

	resolver := newActorResolver(AuthConfig{
		Mode:        OrganizationAuthModeStatic,
		StaticToken: "test-static-token",
	})

	validHeader := http.Header{}
	validHeader.Set("Authorization", "Bearer test-static-token")
	actor, err := resolver.Resolve(validHeader)
	if err != nil {
		t.Fatalf("Resolve with valid token error: %v", err)
	}
	if actor.Subject != "organization-static-admin" {
		t.Fatalf("subject mismatch: got=%s", actor.Subject)
	}
	if !actor.HasScope(authz.ScopeOrganizationAdmin) {
		t.Fatalf("static actor must have organization.admin scope")
	}

	invalidHeader := http.Header{}
	invalidHeader.Set("Authorization", "Bearer wrong-token")
	if _, err := resolver.Resolve(invalidHeader); !errors.Is(err, app.ErrUnauthenticated) {
		t.Fatalf("invalid token must be unauthenticated: %v", err)
	}
}

func TestActorResolverJWTMode(t *testing.T) {
	t.Parallel()

	resolver := newActorResolver(AuthConfig{
		Mode:        OrganizationAuthModeJWT,
		JWTSecret:   "org-jwt-secret",
		JWTIssuer:   "org-issuer",
		JWTAudience: "organization-api",
	})

	token := signHS256JWT(t, "org-jwt-secret", map[string]any{
		"iss":   "org-issuer",
		"aud":   "organization-api",
		"sub":   "user-123",
		"exp":   time.Now().UTC().Add(5 * time.Minute).Unix(),
		"scope": "organization.read organization.write",
	})
	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)

	actor, err := resolver.Resolve(header)
	if err != nil {
		t.Fatalf("Resolve with valid jwt error: %v", err)
	}
	if actor.Subject != "user-123" {
		t.Fatalf("subject mismatch: got=%s want=user-123", actor.Subject)
	}
	if !actor.HasScope(authz.ScopeOrganizationRead) || !actor.HasScope(authz.ScopeOrganizationWrite) {
		t.Fatalf("actor must include scopes from jwt")
	}

	invalidToken := signHS256JWT(t, "wrong-secret", map[string]any{
		"iss":   "org-issuer",
		"aud":   "organization-api",
		"sub":   "user-123",
		"exp":   time.Now().UTC().Add(5 * time.Minute).Unix(),
		"scope": "organization.read",
	})
	invalidHeader := http.Header{}
	invalidHeader.Set("Authorization", "Bearer "+invalidToken)
	if _, err := resolver.Resolve(invalidHeader); !errors.Is(err, app.ErrUnauthenticated) {
		t.Fatalf("invalid signature must be unauthenticated: %v", err)
	}
}

func signHS256JWT(t *testing.T, secret string, claims map[string]any) string {
	t.Helper()

	headerBytes, err := json.Marshal(map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	})
	if err != nil {
		t.Fatalf("marshal header error: %v", err)
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims error: %v", err)
	}
	headerEnc := base64.RawURLEncoding.EncodeToString(headerBytes)
	claimsEnc := base64.RawURLEncoding.EncodeToString(claimsBytes)
	signingInput := headerEnc + "." + claimsEnc

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signingInput))
	signature := mac.Sum(nil)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}
