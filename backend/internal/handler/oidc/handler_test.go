package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

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

const testPrivateJWTClientPrivateKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC0qNCu6+wFHoKW
3vdWz8mu8ebY7tA/z9ukz4b5UOqkC178phzD5vMD7DOb/vnWN1ShxX5l7i/3LBo8
dMD2Rnimnh8GM1dz2uUoZm8fRJSHNJgF4qTViOCefaZZs2zwnK8ZZ0LrmK4Szu4a
cdK2NU/tl3lh3Idm55WTtaWwbQhHGwbECULZPRHwelcrPwH+FLR3Iz1S0AuVSrbh
rOC3jhdkT4QZTHGuRbQT+qMlK9EuQSlsA2PGh0GKqSrPt5G6GIUXD5y7hs8/uMcP
+LgcgTQKh3StSXoFMpVOZzbJtseJyOwurAD/MbyME/eH2WStpKACuZuLKNe0t4pW
sEWA4W5PAgMBAAECggEAD0bvTrt4m/42gNeeBuNPZNHj+ZhIV/0Vz9wUx+SF0xV7
FNZfPFm9VymUO67WJb1MFNoElE4OFFLQbShaYPkYns5kRTv2Oz/ZfQ8ceoJsJPrX
mDfQRJZsmDp75L39imNVk0peKFoi7kg9blMNxIbBmY/jndjuQk93IKSNvFucBZco
vDbP2Y5Fqa/OP01q7Y1gWZ9CJDDPwEQT66B2HLVhrcmui4/E6qIo1Id/zjs5TMm/
NTbV3E2Y4jsjaAKmz5sLEFoQmW+HGoUL2K/4FmB7Ym+WfxD7fLWxFsODZjloCOq4
HUFUHnVXTJWwe02qtYXKBmw5FruRgDNpLwN3GJUwoQKBgQD4lAlXX7/YgnXe74U2
ASoJGQqg84N8wElMzu7nf32d+3F5B7nxBaTpN57YHOtpefD+ZgfEa3+q8L+5uQLH
58MwpffF1PCqJR3IO3SMCBzwHolL61gs+IGous5nGm+3Fgs5TvUs6EtL+mnsHQX9
Ut/xk7+0XAfDyhCDS97iPepRtwKBgQC6Dac6E9wMQVPU7+SPhekCz3icNoNYXgVg
2SsXvpnVXxqh+A8zZ+iZxbV73tC7lvqG5wgjIxGyI9egzISeHIaKVJYWHYzKAnxm
IRzB0ghaVEBDnIzx4R+EzoLQ5dcUx3/wCMJQLEQhNp5yeTsm6C/2NQoALSikgq0+
6nP7JBhoKQKBgQDjNHwtTqlNvkD6mjdKG1pOooLihnHCjwbwm5wmIJOy2Obo1zUP
pjcLq/kWU6ig6gJqpNuonxE8L30uxnpSOfZg+vIz8uRewDoukJmAfNHmcCLSL7SS
tjnc/ZI3DyTZVd7AbPkQKOrZ8XLri8OzvhJO/tsUgaHfRUw+lhSM+ka4lQKBgQCT
jsqHJEMMMS+UnSIPtivEP9mvQwjOp9rqIbKspU0KTeAofz1HDu0KMCSsdl3juW0+
WrM4ctLRDt4wOKQhZgxKX6WdKpiDio8wzKgrDDH1ugYx2VJrb5l40fQsS21WnJba
P4gk38a09MWbkoyYYePQB+bDlw051C4kzPtpPgphaQKBgQD1mrOH6LrSogKR8F4h
slXGSdUuRgQ04Xx7yuINDGg9BNsk0/WCYQRHk5i4wdbX+KF5VXlFn/4y247SdM6D
oXwN7iwKj3XeiEQ1VZ9VOyF40bEJYi8crBx+gUIVSMcprL69Eej9m8ZrIJZU7ZuV
cweQ8NEor3To+VWCEMpkqZLHtA==
-----END PRIVATE KEY-----
`

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
	tokenAuthMethods, ok := doc["token_endpoint_auth_methods_supported"].([]any)
	if !ok {
		t.Fatalf("token_endpoint_auth_methods_supported must be array")
	}
	if !containsValue(tokenAuthMethods, "none") {
		t.Fatalf("token_endpoint_auth_methods_supported must include none")
	}
	if !containsValue(tokenAuthMethods, "client_secret_basic") {
		t.Fatalf("token_endpoint_auth_methods_supported must include client_secret_basic")
	}
	if !containsValue(tokenAuthMethods, "private_key_jwt") {
		t.Fatalf("token_endpoint_auth_methods_supported must include private_key_jwt")
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
	if idTokenClaims["azp"] != testClientID {
		t.Fatalf("id_token azp mismatch: %v", idTokenClaims["azp"])
	}
	sid, ok := idTokenClaims["sid"].(string)
	if !ok || sid == "" {
		t.Fatalf("id_token must include non-empty sid")
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
	if refreshIDTokenClaims["azp"] != testClientID {
		t.Fatalf("refresh id_token azp mismatch: %v", refreshIDTokenClaims["azp"])
	}
	if refreshIDTokenClaims["sid"] != sid {
		t.Fatalf("refresh id_token sid mismatch: got=%v want=%v", refreshIDTokenClaims["sid"], sid)
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

func TestTokenFlowWithClientSecretBasic(t *testing.T) {
	t.Parallel()

	provider, err := core.NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}
	h := NewHandler(provider)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	codeChallenge := pkceS256(testCodeVerifier)
	authReq := httptest.NewRequest(
		http.MethodGet,
		"/oauth2/authorize?response_type=code&client_id="+url.QueryEscape(core.DefaultConfidentialClientID)+
			"&redirect_uri="+url.QueryEscape(core.DefaultConfidentialRedirect)+
			"&scope="+url.QueryEscape("openid")+
			"&state="+url.QueryEscape("handler-confidential-state")+
			"&code_challenge="+url.QueryEscape(codeChallenge)+
			"&code_challenge_method=S256",
		nil,
	)
	authRec := httptest.NewRecorder()
	mux.ServeHTTP(authRec, authReq)
	if authRec.Code != http.StatusFound {
		t.Fatalf("expected 302 for authorize, got %d", authRec.Code)
	}
	code := queryParam(t, authRec.Header().Get("Location"), "code")
	if code == "" {
		t.Fatalf("authorize redirect must include code")
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {core.DefaultConfidentialRedirect},
		"code_verifier": {testCodeVerifier},
	}
	tokenReq := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(core.DefaultConfidentialClientID+":wrong-secret")))
	tokenRec := httptest.NewRecorder()
	mux.ServeHTTP(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid basic credentials, got %d", tokenRec.Code)
	}
	var tokenErr map[string]string
	if err := json.Unmarshal(tokenRec.Body.Bytes(), &tokenErr); err != nil {
		t.Fatalf("invalid token error json: %v", err)
	}
	if tokenErr["error"] != "invalid_client" {
		t.Fatalf("expected invalid_client, got %s", tokenErr["error"])
	}

	validReq := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	validReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	validReq.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(core.DefaultConfidentialClientID+":"+core.DefaultConfidentialClientSecret)))
	validRec := httptest.NewRecorder()
	mux.ServeHTTP(validRec, validReq)
	if validRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid basic credentials, got %d", validRec.Code)
	}
	var tokenResp map[string]any
	if err := json.Unmarshal(validRec.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("invalid token json: %v", err)
	}
	if tokenResp["access_token"] == "" {
		t.Fatalf("token response must include access_token")
	}
}

func TestTokenFlowWithPrivateKeyJWT(t *testing.T) {
	t.Parallel()

	provider, err := core.NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}
	h := NewHandler(provider)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	codeChallenge := pkceS256(testCodeVerifier)
	authReq := httptest.NewRequest(
		http.MethodGet,
		"/oauth2/authorize?response_type=code&client_id="+url.QueryEscape(core.DefaultPrivateJWTClientID)+
			"&redirect_uri="+url.QueryEscape(core.DefaultPrivateJWTRedirect)+
			"&scope="+url.QueryEscape("openid")+
			"&state="+url.QueryEscape("handler-private-jwt-state")+
			"&code_challenge="+url.QueryEscape(codeChallenge)+
			"&code_challenge_method=S256",
		nil,
	)
	authRec := httptest.NewRecorder()
	mux.ServeHTTP(authRec, authReq)
	if authRec.Code != http.StatusFound {
		t.Fatalf("expected 302 for authorize, got %d", authRec.Code)
	}
	code := queryParam(t, authRec.Header().Get("Location"), "code")
	if code == "" {
		t.Fatalf("authorize redirect must include code")
	}

	invalidAssertion := signClientAssertion(
		t,
		testPrivateJWTClientPrivateKeyPEM,
		core.DefaultPrivateJWTClientID,
		"http://invalid.example/token",
		time.Now().UTC().Add(5*time.Minute),
	)

	form := url.Values{
		"grant_type":            {"authorization_code"},
		"code":                  {code},
		"redirect_uri":          {core.DefaultPrivateJWTRedirect},
		"client_id":             {core.DefaultPrivateJWTClientID},
		"code_verifier":         {testCodeVerifier},
		"client_assertion_type": {core.ClientAssertionTypeJWTBearer},
		"client_assertion":      {invalidAssertion},
	}
	invalidReq := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	invalidReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	invalidRec := httptest.NewRecorder()
	mux.ServeHTTP(invalidRec, invalidReq)
	if invalidRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid private_key_jwt assertion, got %d", invalidRec.Code)
	}
	var invalidErr map[string]string
	if err := json.Unmarshal(invalidRec.Body.Bytes(), &invalidErr); err != nil {
		t.Fatalf("invalid token error json: %v", err)
	}
	if invalidErr["error"] != "invalid_client" {
		t.Fatalf("expected invalid_client, got %s", invalidErr["error"])
	}

	validForm := url.Values{
		"grant_type":            {"authorization_code"},
		"code":                  {code},
		"redirect_uri":          {core.DefaultPrivateJWTRedirect},
		"client_id":             {core.DefaultPrivateJWTClientID},
		"code_verifier":         {testCodeVerifier},
		"client_assertion_type": {core.ClientAssertionTypeJWTBearer},
		"client_assertion": {signClientAssertion(
			t,
			testPrivateJWTClientPrivateKeyPEM,
			core.DefaultPrivateJWTClientID,
			testIssuer+"/oauth2/token",
			time.Now().UTC().Add(5*time.Minute),
		)},
	}
	validReq := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(validForm.Encode()))
	validReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	validRec := httptest.NewRecorder()
	mux.ServeHTTP(validRec, validReq)
	if validRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid private_key_jwt assertion, got %d", validRec.Code)
	}
	var tokenResp map[string]any
	if err := json.Unmarshal(validRec.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("invalid token json: %v", err)
	}
	if tokenResp["access_token"] == "" {
		t.Fatalf("token response must include access_token")
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

func signClientAssertion(t *testing.T, privateKeyPEM, clientID, audience string, expiresAt time.Time) string {
	t.Helper()

	privateKey := parseRSAPrivateKey(t, privateKeyPEM)
	now := time.Now().UTC()
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
	}
	claims := map[string]any{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"exp": expiresAt.Unix(),
		"iat": now.Unix(),
		"jti": fmt.Sprintf("jti-%d", now.UnixNano()),
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal jwt header error: %v", err)
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal jwt claims error: %v", err)
	}

	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsBytes)
	signingInput := headerEncoded + "." + claimsEncoded

	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign jwt error: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func parseRSAPrivateKey(t *testing.T, privateKeyPEM string) *rsa.PrivateKey {
	t.Helper()

	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		t.Fatalf("decode private key pem error")
	}
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		privateKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("private key is not rsa")
		}
		return privateKey
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse rsa private key error: %v", err)
	}
	return privateKey
}
