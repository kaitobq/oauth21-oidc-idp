package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	core "github.com/kaitobq/oauth21-oidc-idp/backend/internal/oidc"
)

const (
	testIssuer       = "http://localhost:8080"
	testClientID     = "test-client"
	testRedirectURI  = "http://localhost:3000/callback"
	testCodeVerifier = "this-is-a-long-enough-code-verifier-for-handler-tests-123456789"
)

func TestDiscoveryEndpoint(t *testing.T) {
	t.Parallel()

	provider, err := core.NewProvider(testIssuer, testClientID, testRedirectURI)
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
	grantTypes, ok := doc["grant_types_supported"].([]any)
	if !ok {
		t.Fatalf("grant_types_supported must be array")
	}
	if !containsValue(grantTypes, "refresh_token") {
		t.Fatalf("grant_types_supported must include refresh_token")
	}
}

func TestAuthorizeAndTokenFlow(t *testing.T) {
	t.Parallel()

	provider, err := core.NewProvider(testIssuer, testClientID, testRedirectURI)
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

	codeChallenge := pkceS256(testCodeVerifier)
	authReq := httptest.NewRequest(
		http.MethodGet,
		"/oauth2/authorize?response_type=code&client_id="+url.QueryEscape(testClientID)+
			"&redirect_uri="+url.QueryEscape(testRedirectURI)+
			"&scope="+url.QueryEscape("openid profile offline_access")+
			"&state="+url.QueryEscape("handler-state")+
			"&code_challenge="+url.QueryEscape(codeChallenge)+
			"&code_challenge_method=S256",
		nil,
	)
	authRec := httptest.NewRecorder()
	mux.ServeHTTP(authRec, authReq)
	if authRec.Code != http.StatusFound {
		t.Fatalf("expected 302 for authorize, got %d", authRec.Code)
	}
	location := authRec.Header().Get("Location")
	if location == "" {
		t.Fatalf("authorize response must include Location header")
	}
	code := queryParam(t, location, "code")
	if code == "" {
		t.Fatalf("authorize redirect must include code")
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRedirectURI},
		"client_id":     {testClientID},
		"code_verifier": {testCodeVerifier},
	}
	tokenReq := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRec := httptest.NewRecorder()
	mux.ServeHTTP(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for token, got %d", tokenRec.Code)
	}

	var tokenResp map[string]any
	if err := json.Unmarshal(tokenRec.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("invalid token json: %v", err)
	}
	if tokenResp["access_token"] == "" {
		t.Fatalf("access_token must not be empty")
	}
	if tokenResp["id_token"] == "" {
		t.Fatalf("id_token must not be empty for openid scope")
	}
	refreshToken, ok := tokenResp["refresh_token"].(string)
	if !ok || refreshToken == "" {
		t.Fatalf("refresh_token must not be empty for offline_access scope")
	}

	reuseReq := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	reuseReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reuseRec := httptest.NewRecorder()
	mux.ServeHTTP(reuseRec, reuseReq)
	if reuseRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for reused code, got %d", reuseRec.Code)
	}

	var reuseErr map[string]string
	if err := json.Unmarshal(reuseRec.Body.Bytes(), &reuseErr); err != nil {
		t.Fatalf("invalid reuse error json: %v", err)
	}
	if reuseErr["error"] != "invalid_grant" {
		t.Fatalf("expected invalid_grant, got %s", reuseErr["error"])
	}

	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {testClientID},
	}
	refreshReq := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(refreshForm.Encode()))
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshRec := httptest.NewRecorder()
	mux.ServeHTTP(refreshRec, refreshReq)
	if refreshRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for refresh token exchange, got %d", refreshRec.Code)
	}

	var refreshResp map[string]any
	if err := json.Unmarshal(refreshRec.Body.Bytes(), &refreshResp); err != nil {
		t.Fatalf("invalid refresh token json: %v", err)
	}
	nextRefreshToken, ok := refreshResp["refresh_token"].(string)
	if !ok || nextRefreshToken == "" {
		t.Fatalf("refresh exchange must return rotated refresh_token")
	}
	if nextRefreshToken == refreshToken {
		t.Fatalf("refresh token must be rotated")
	}

	reuseRefreshReq := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(refreshForm.Encode()))
	reuseRefreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reuseRefreshRec := httptest.NewRecorder()
	mux.ServeHTTP(reuseRefreshRec, reuseRefreshReq)
	if reuseRefreshRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for reused refresh token, got %d", reuseRefreshRec.Code)
	}

	var reuseRefreshErr map[string]string
	if err := json.Unmarshal(reuseRefreshRec.Body.Bytes(), &reuseRefreshErr); err != nil {
		t.Fatalf("invalid reuse refresh error json: %v", err)
	}
	if reuseRefreshErr["error"] != "invalid_grant" {
		t.Fatalf("expected invalid_grant for refresh reuse, got %s", reuseRefreshErr["error"])
	}
}

func queryParam(t *testing.T, rawURL, name string) string {
	t.Helper()

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url error: %v", err)
	}
	return parsed.Query().Get(name)
}

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func containsValue(values []any, target string) bool {
	for _, v := range values {
		if s, ok := v.(string); ok && s == target {
			return true
		}
	}
	return false
}
