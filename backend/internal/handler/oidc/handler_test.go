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
	testIssuer           = "http://localhost:8080"
	testClientID         = "test-client"
	testRedirectURI      = "http://localhost:3000/callback"
	testCodeVerifier     = "this-is-a-long-enough-code-verifier-for-handler-tests-123456789"
	testNonce            = "nonce-handler-test-123"
	coreDefaultACRValue  = "urn:example:loa:1"
	coreDefaultAMRMethod = "pwd"
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
	acrValues, ok := doc["acr_values_supported"].([]any)
	if !ok {
		t.Fatalf("acr_values_supported must be array")
	}
	if !containsValue(acrValues, coreDefaultACRValue) {
		t.Fatalf("acr_values_supported must include %s", coreDefaultACRValue)
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
			"&nonce="+url.QueryEscape(testNonce)+
			"&acr_values="+url.QueryEscape(coreDefaultACRValue)+
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
	accessToken, ok := tokenResp["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatalf("access_token must not be empty")
	}
	if tokenResp["id_token"] == "" {
		t.Fatalf("id_token must not be empty for openid scope")
	}
	idToken, ok := tokenResp["id_token"].(string)
	if !ok || idToken == "" {
		t.Fatalf("id_token must be string")
	}
	idTokenClaims := parseJWTClaims(t, idToken)
	if idTokenClaims["nonce"] != testNonce {
		t.Fatalf("id_token nonce mismatch: %v", idTokenClaims["nonce"])
	}
	authTime, ok := idTokenClaims["auth_time"].(float64)
	if !ok {
		t.Fatalf("id_token must include numeric auth_time")
	}
	if idTokenClaims["acr"] != coreDefaultACRValue {
		t.Fatalf("id_token acr mismatch: %v", idTokenClaims["acr"])
	}
	if !claimHasStringValue(t, idTokenClaims, "amr", coreDefaultAMRMethod) {
		t.Fatalf("id_token amr must include %s", coreDefaultAMRMethod)
	}
	if idTokenClaims["at_hash"] != accessTokenHash(accessToken) {
		t.Fatalf("id_token at_hash mismatch: %v", idTokenClaims["at_hash"])
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
	refreshAccessToken, ok := refreshResp["access_token"].(string)
	if !ok || refreshAccessToken == "" {
		t.Fatalf("refresh exchange must return access_token")
	}
	nextRefreshToken, ok := refreshResp["refresh_token"].(string)
	if !ok || nextRefreshToken == "" {
		t.Fatalf("refresh exchange must return rotated refresh_token")
	}
	if nextRefreshToken == refreshToken {
		t.Fatalf("refresh token must be rotated")
	}
	refreshIDToken, ok := refreshResp["id_token"].(string)
	if !ok || refreshIDToken == "" {
		t.Fatalf("refresh exchange must return id_token")
	}
	refreshIDTokenClaims := parseJWTClaims(t, refreshIDToken)
	if _, ok := refreshIDTokenClaims["nonce"]; ok {
		t.Fatalf("refresh id_token must not include nonce")
	}
	if refreshIDTokenClaims["auth_time"] != authTime {
		t.Fatalf("refresh id_token auth_time mismatch: got=%v want=%v", refreshIDTokenClaims["auth_time"], authTime)
	}
	if refreshIDTokenClaims["acr"] != coreDefaultACRValue {
		t.Fatalf("refresh id_token acr mismatch: %v", refreshIDTokenClaims["acr"])
	}
	if !claimHasStringValue(t, refreshIDTokenClaims, "amr", coreDefaultAMRMethod) {
		t.Fatalf("refresh id_token amr must include %s", coreDefaultAMRMethod)
	}
	if refreshIDTokenClaims["at_hash"] != accessTokenHash(refreshAccessToken) {
		t.Fatalf("refresh id_token at_hash mismatch: %v", refreshIDTokenClaims["at_hash"])
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

func parseJWTClaims(t *testing.T, rawToken string) map[string]any {
	t.Helper()

	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid jwt format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode jwt payload error: %v", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal jwt claims error: %v", err)
	}
	return claims
}

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func accessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

func containsValue(values []any, target string) bool {
	for _, v := range values {
		if s, ok := v.(string); ok && s == target {
			return true
		}
	}
	return false
}

func claimHasStringValue(t *testing.T, claims map[string]any, claimName, target string) bool {
	t.Helper()

	values, ok := claims[claimName].([]any)
	if !ok {
		return false
	}
	for _, v := range values {
		if s, ok := v.(string); ok && s == target {
			return true
		}
	}
	return false
}
