package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	core "github.com/kaitobq/oauth21-oidc-idp/backend/internal/oidc"
)

func TestDiscoveryEndpoint(t *testing.T) {
	t.Parallel()

	provider, err := core.NewProvider("http://localhost:8080")
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}
	h := NewHandler(provider)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var doc map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("invalid json: %v", err)
	}

	for _, f := range []string{"issuer", "jwks_uri", "authorization_endpoint", "token_endpoint", "grant_types_supported", "code_challenge_methods_supported"} {
		if _, ok := doc[f]; !ok {
			t.Fatalf("missing field: %s", f)
		}
	}
}

func TestJWKSAndPlaceholders(t *testing.T) {
	t.Parallel()

	provider, err := core.NewProvider("http://localhost:8080")
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}
	h := NewHandler(provider)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	jwksReq := httptest.NewRequest(http.MethodGet, "/oauth2/jwks", nil)
	jwksRec := httptest.NewRecorder()
	mux.ServeHTTP(jwksRec, jwksReq)
	if jwksRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for jwks, got %d", jwksRec.Code)
	}

	authReq := httptest.NewRequest(http.MethodGet, "/oauth2/authorize", nil)
	authRec := httptest.NewRecorder()
	mux.ServeHTTP(authRec, authReq)
	if authRec.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 for authorize, got %d", authRec.Code)
	}

	tokenReq := httptest.NewRequest(http.MethodPost, "/oauth2/token", nil)
	tokenRec := httptest.NewRecorder()
	mux.ServeHTTP(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 for token, got %d", tokenRec.Code)
	}
}
