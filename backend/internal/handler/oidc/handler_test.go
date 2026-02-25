package oidc

import (
	"crypto"
	"crypto/hmac"
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

	"github.com/kaitobq/oauth21-oidc-idp/backend/internal/handler/middleware"
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
	privateKeyPEM := mustGenerateTestPrivateKeyPEM(t)
	if err := provider.RegisterPrivateJWTClient(
		core.DefaultPrivateJWTClientID,
		core.DefaultPrivateJWTRedirect,
		mustPublicKeyPEMFromPrivateKey(t, privateKeyPEM),
	); err != nil {
		t.Fatalf("RegisterPrivateJWTClient error: %v", err)
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

	for _, f := range []string{"issuer", "jwks_uri", "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "grant_types_supported", "code_challenge_methods_supported"} {
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
	privateKeyPEM := mustGenerateTestPrivateKeyPEM(t)
	if err := provider.RegisterPrivateJWTClient(
		core.DefaultPrivateJWTClientID,
		core.DefaultPrivateJWTRedirect,
		mustPublicKeyPEMFromPrivateKey(t, privateKeyPEM),
	); err != nil {
		t.Fatalf("RegisterPrivateJWTClient error: %v", err)
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
	privateKeyPEM := mustGenerateTestPrivateKeyPEM(t)
	if err := provider.RegisterPrivateJWTClient(
		core.DefaultPrivateJWTClientID,
		core.DefaultPrivateJWTRedirect,
		mustPublicKeyPEMFromPrivateKey(t, privateKeyPEM),
	); err != nil {
		t.Fatalf("RegisterPrivateJWTClient error: %v", err)
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
	privateKeyPEM := mustGenerateTestPrivateKeyPEM(t)
	if err := provider.RegisterPrivateJWTClient(
		core.DefaultPrivateJWTClientID,
		core.DefaultPrivateJWTRedirect,
		mustPublicKeyPEMFromPrivateKey(t, privateKeyPEM),
	); err != nil {
		t.Fatalf("RegisterPrivateJWTClient error: %v", err)
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
		privateKeyPEM,
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
			privateKeyPEM,
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

func TestTokenFlowWithPrivateKeyJWTReplayAssertion(t *testing.T) {
	t.Parallel()

	provider, err := core.NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}
	privateKeyPEM := mustGenerateTestPrivateKeyPEM(t)
	if err := provider.RegisterPrivateJWTClient(
		core.DefaultPrivateJWTClientID,
		core.DefaultPrivateJWTRedirect,
		mustPublicKeyPEMFromPrivateKey(t, privateKeyPEM),
	); err != nil {
		t.Fatalf("RegisterPrivateJWTClient error: %v", err)
	}
	h := NewHandler(provider)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	authorizeCode := func(state string) string {
		codeChallenge := pkceS256(testCodeVerifier)
		authReq := httptest.NewRequest(
			http.MethodGet,
			"/oauth2/authorize?response_type=code&client_id="+url.QueryEscape(core.DefaultPrivateJWTClientID)+
				"&redirect_uri="+url.QueryEscape(core.DefaultPrivateJWTRedirect)+
				"&scope="+url.QueryEscape("openid")+
				"&state="+url.QueryEscape(state)+
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
		return code
	}

	code1 := authorizeCode("handler-private-jwt-replay-state-1")
	code2 := authorizeCode("handler-private-jwt-replay-state-2")

	replayAssertion := signClientAssertion(
		t,
		privateKeyPEM,
		core.DefaultPrivateJWTClientID,
		testIssuer+"/oauth2/token",
		time.Now().UTC().Add(5*time.Minute),
	)

	form1 := url.Values{
		"grant_type":            {"authorization_code"},
		"code":                  {code1},
		"redirect_uri":          {core.DefaultPrivateJWTRedirect},
		"client_id":             {core.DefaultPrivateJWTClientID},
		"code_verifier":         {testCodeVerifier},
		"client_assertion_type": {core.ClientAssertionTypeJWTBearer},
		"client_assertion":      {replayAssertion},
	}
	req1 := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form1.Encode()))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec1 := httptest.NewRecorder()
	mux.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200 for first private_key_jwt assertion, got %d", rec1.Code)
	}

	form2 := url.Values{
		"grant_type":            {"authorization_code"},
		"code":                  {code2},
		"redirect_uri":          {core.DefaultPrivateJWTRedirect},
		"client_id":             {core.DefaultPrivateJWTClientID},
		"code_verifier":         {testCodeVerifier},
		"client_assertion_type": {core.ClientAssertionTypeJWTBearer},
		"client_assertion":      {replayAssertion},
	}
	req2 := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for replayed private_key_jwt assertion, got %d", rec2.Code)
	}

	var errResp map[string]string
	if err := json.Unmarshal(rec2.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("invalid token error json: %v", err)
	}
	if errResp["error"] != "invalid_client" {
		t.Fatalf("expected invalid_client, got %s", errResp["error"])
	}
}

func TestUserInfoEndpoint(t *testing.T) {
	t.Parallel()

	provider, err := core.NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}
	privateKeyPEM := mustGenerateTestPrivateKeyPEM(t)
	if err := provider.RegisterPrivateJWTClient(
		core.DefaultPrivateJWTClientID,
		core.DefaultPrivateJWTRedirect,
		mustPublicKeyPEMFromPrivateKey(t, privateKeyPEM),
	); err != nil {
		t.Fatalf("RegisterPrivateJWTClient error: %v", err)
	}
	h := NewHandler(provider)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	codeChallenge := pkceS256(testCodeVerifier)
	authReq := httptest.NewRequest(
		http.MethodGet,
		"/oauth2/authorize?response_type=code&client_id="+url.QueryEscape(testClientID)+
			"&redirect_uri="+url.QueryEscape(testRedirectURI)+
			"&scope="+url.QueryEscape("openid profile email")+
			"&state="+url.QueryEscape("handler-userinfo-state")+
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

	userInfoReq := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	userInfoReq.Header.Set("Authorization", "Bearer "+accessToken)
	userInfoRec := httptest.NewRecorder()
	mux.ServeHTTP(userInfoRec, userInfoReq)
	if userInfoRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for userinfo, got %d", userInfoRec.Code)
	}
	var userInfo map[string]any
	if err := json.Unmarshal(userInfoRec.Body.Bytes(), &userInfo); err != nil {
		t.Fatalf("invalid userinfo json: %v", err)
	}
	if userInfo["sub"] == "" {
		t.Fatalf("userinfo response must include sub")
	}
	if userInfo["name"] == "" {
		t.Fatalf("userinfo response must include name with profile scope")
	}
	if userInfo["email"] == "" {
		t.Fatalf("userinfo response must include email with email scope")
	}
}

func TestUserInfoEndpointRejectsInvalidTokenAndInsufficientScope(t *testing.T) {
	t.Parallel()

	provider, err := core.NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}
	privateKeyPEM := mustGenerateTestPrivateKeyPEM(t)
	if err := provider.RegisterPrivateJWTClient(
		core.DefaultPrivateJWTClientID,
		core.DefaultPrivateJWTRedirect,
		mustPublicKeyPEMFromPrivateKey(t, privateKeyPEM),
	); err != nil {
		t.Fatalf("RegisterPrivateJWTClient error: %v", err)
	}
	h := NewHandler(provider)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	invalidReq := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	invalidReq.Header.Set("Authorization", "Bearer invalid-token")
	invalidRec := httptest.NewRecorder()
	mux.ServeHTTP(invalidRec, invalidReq)
	if invalidRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid token, got %d", invalidRec.Code)
	}
	if header := invalidRec.Header().Get("WWW-Authenticate"); !strings.Contains(header, `error="invalid_token"`) {
		t.Fatalf("WWW-Authenticate must include invalid_token, got %q", header)
	}
	assertTokenErrorContract(t, invalidRec, http.StatusUnauthorized, "invalid_token")

	codeChallenge := pkceS256(testCodeVerifier)
	authReq := httptest.NewRequest(
		http.MethodGet,
		"/oauth2/authorize?response_type=code&client_id="+url.QueryEscape(testClientID)+
			"&redirect_uri="+url.QueryEscape(testRedirectURI)+
			"&scope="+url.QueryEscape("profile")+
			"&state="+url.QueryEscape("handler-userinfo-no-openid-state")+
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

	scopeReq := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	scopeReq.Header.Set("Authorization", "Bearer "+accessToken)
	scopeRec := httptest.NewRecorder()
	mux.ServeHTTP(scopeRec, scopeReq)
	if scopeRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for insufficient scope, got %d", scopeRec.Code)
	}
	if header := scopeRec.Header().Get("WWW-Authenticate"); !strings.Contains(header, `error="insufficient_scope"`) {
		t.Fatalf("WWW-Authenticate must include insufficient_scope, got %q", header)
	}
	assertTokenErrorContract(t, scopeRec, http.StatusForbidden, "insufficient_scope")
}

func TestTokenErrorContract(t *testing.T) {
	t.Parallel()

	provider, err := core.NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}
	privateKeyPEM := mustGenerateTestPrivateKeyPEM(t)
	if err := provider.RegisterPrivateJWTClient(
		core.DefaultPrivateJWTClientID,
		core.DefaultPrivateJWTRedirect,
		mustPublicKeyPEMFromPrivateKey(t, privateKeyPEM),
	); err != nil {
		t.Fatalf("RegisterPrivateJWTClient error: %v", err)
	}
	h := NewHandler(provider)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	t.Run("unsupported_grant_type", func(t *testing.T) {
		form := url.Values{
			"grant_type": {"password"},
			"client_id":  {testClientID},
		}
		req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		assertTokenErrorContract(t, rec, http.StatusBadRequest, "unsupported_grant_type")
	})

	t.Run("invalid_grant", func(t *testing.T) {
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"invalid-code"},
			"redirect_uri":  {testRedirectURI},
			"client_id":     {testClientID},
			"code_verifier": {testCodeVerifier},
		}
		req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		assertTokenErrorContract(t, rec, http.StatusBadRequest, "invalid_grant")
	})

	t.Run("invalid_client", func(t *testing.T) {
		codeChallenge := pkceS256(testCodeVerifier)
		authReq := httptest.NewRequest(
			http.MethodGet,
			"/oauth2/authorize?response_type=code&client_id="+url.QueryEscape(core.DefaultConfidentialClientID)+
				"&redirect_uri="+url.QueryEscape(core.DefaultConfidentialRedirect)+
				"&scope="+url.QueryEscape("openid")+
				"&state="+url.QueryEscape("error-contract-state")+
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
		req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(core.DefaultConfidentialClientID+":wrong-secret")))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		assertTokenErrorContract(t, rec, http.StatusUnauthorized, "invalid_client")
	})
}

func TestRotateSigningKeyEndpointDisabledByDefault(t *testing.T) {
	t.Parallel()

	provider, err := core.NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}
	h := NewHandler(provider)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/admin/rotate-signing-key", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("rotate endpoint must be disabled by default: got=%d want=%d", rec.Code, http.StatusNotFound)
	}
}

func TestRotateSigningKeyEndpoint(t *testing.T) {
	t.Parallel()

	provider, err := core.NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}
	h := NewHandlerWithSigningKeyRotation(provider, "test-rotation-token")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	initialKID := provider.JWKS().Keys[0].Kid
	if initialKID == "" {
		t.Fatalf("initial kid must not be empty")
	}

	methodReq := httptest.NewRequest(http.MethodGet, "/oauth2/admin/rotate-signing-key", nil)
	methodRec := httptest.NewRecorder()
	mux.ServeHTTP(methodRec, methodReq)
	if methodRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method check failed: got=%d want=%d", methodRec.Code, http.StatusMethodNotAllowed)
	}

	missingAuthReq := httptest.NewRequest(http.MethodPost, "/oauth2/admin/rotate-signing-key", nil)
	missingAuthRec := httptest.NewRecorder()
	mux.ServeHTTP(missingAuthRec, missingAuthReq)
	if missingAuthRec.Code != http.StatusUnauthorized {
		t.Fatalf("missing auth must be rejected: got=%d want=%d", missingAuthRec.Code, http.StatusUnauthorized)
	}

	invalidTokenReq := httptest.NewRequest(http.MethodPost, "/oauth2/admin/rotate-signing-key", nil)
	invalidTokenReq.Header.Set("Authorization", "Bearer wrong-token")
	invalidTokenRec := httptest.NewRecorder()
	mux.ServeHTTP(invalidTokenRec, invalidTokenReq)
	if invalidTokenRec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token must be rejected: got=%d want=%d", invalidTokenRec.Code, http.StatusUnauthorized)
	}

	rotateReq := httptest.NewRequest(http.MethodPost, "/oauth2/admin/rotate-signing-key", nil)
	rotateReq.Header.Set("Authorization", "Bearer test-rotation-token")
	rotateRec := httptest.NewRecorder()
	mux.ServeHTTP(rotateRec, rotateReq)
	if rotateRec.Code != http.StatusOK {
		t.Fatalf("rotate request failed: got=%d want=%d", rotateRec.Code, http.StatusOK)
	}

	var rotateResp map[string]string
	if err := json.Unmarshal(rotateRec.Body.Bytes(), &rotateResp); err != nil {
		t.Fatalf("rotate response json error: %v", err)
	}
	rotatedKID := rotateResp["kid"]
	if rotatedKID == "" {
		t.Fatalf("rotate response must include kid")
	}
	if rotatedKID == initialKID {
		t.Fatalf("rotated kid must differ from initial kid")
	}

	jwksReq := httptest.NewRequest(http.MethodGet, "/oauth2/jwks", nil)
	jwksRec := httptest.NewRecorder()
	mux.ServeHTTP(jwksRec, jwksReq)
	if jwksRec.Code != http.StatusOK {
		t.Fatalf("jwks endpoint status mismatch: got=%d want=%d", jwksRec.Code, http.StatusOK)
	}

	var jwksDoc struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(jwksRec.Body.Bytes(), &jwksDoc); err != nil {
		t.Fatalf("jwks json error: %v", err)
	}
	if len(jwksDoc.Keys) != 2 {
		t.Fatalf("jwks key count mismatch after rotation: got=%d want=%d", len(jwksDoc.Keys), 2)
	}
	if jwksDoc.Keys[0].Kid != rotatedKID {
		t.Fatalf("jwks active kid mismatch: got=%s want=%s", jwksDoc.Keys[0].Kid, rotatedKID)
	}
	if jwksDoc.Keys[1].Kid != initialKID {
		t.Fatalf("jwks must retain previous key after rotation: got=%s want=%s", jwksDoc.Keys[1].Kid, initialKID)
	}
}

func TestRotateSigningKeyEndpointWithoutTokenConfig(t *testing.T) {
	t.Parallel()

	provider, err := core.NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}
	h := NewHandlerWithSigningKeyRotation(provider, "   ")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/admin/rotate-signing-key", nil)
	req.Header.Set("Authorization", "Bearer any-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("misconfigured token must return 500: got=%d want=%d", rec.Code, http.StatusInternalServerError)
	}
}

func TestRotateSigningKeyEndpointWithJWTAdminAuth(t *testing.T) {
	t.Parallel()

	provider, err := core.NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}
	h := NewHandlerWithSigningKeyRotationAuth(
		provider,
		"unused-static-token",
		middleware.AdminAuthModeJWT,
		"test-admin-jwt-secret",
		"test-admin-issuer",
		"oidc-admin",
	)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	invalidScopeToken := signAdminJWT(
		t,
		"test-admin-jwt-secret",
		map[string]any{
			"iss":   "test-admin-issuer",
			"aud":   "oidc-admin",
			"exp":   time.Now().UTC().Add(5 * time.Minute).Unix(),
			"scope": middleware.ScopeRotatePrivateJWTClientKey,
		},
	)
	invalidScopeReq := httptest.NewRequest(http.MethodPost, "/oauth2/admin/rotate-signing-key", nil)
	invalidScopeReq.Header.Set("Authorization", "Bearer "+invalidScopeToken)
	invalidScopeRec := httptest.NewRecorder()
	mux.ServeHTTP(invalidScopeRec, invalidScopeReq)
	if invalidScopeRec.Code != http.StatusForbidden {
		t.Fatalf("insufficient scope must be rejected: got=%d want=%d", invalidScopeRec.Code, http.StatusForbidden)
	}

	validToken := signAdminJWT(
		t,
		"test-admin-jwt-secret",
		map[string]any{
			"iss":   "test-admin-issuer",
			"aud":   "oidc-admin",
			"exp":   time.Now().UTC().Add(5 * time.Minute).Unix(),
			"scope": middleware.ScopeRotateSigningKey,
		},
	)
	validReq := httptest.NewRequest(http.MethodPost, "/oauth2/admin/rotate-signing-key", nil)
	validReq.Header.Set("Authorization", "Bearer "+validToken)
	validRec := httptest.NewRecorder()
	mux.ServeHTTP(validRec, validReq)
	if validRec.Code != http.StatusOK {
		t.Fatalf("valid jwt scope must be accepted: got=%d want=%d", validRec.Code, http.StatusOK)
	}
}

func TestRotatePrivateJWTClientKeyEndpointDisabledByDefault(t *testing.T) {
	t.Parallel()

	provider, err := core.NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}
	h := NewHandler(provider)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/admin/rotate-private-jwt-client-key", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("private_jwt rotate endpoint must be disabled by default: got=%d want=%d", rec.Code, http.StatusNotFound)
	}
}

func TestRotatePrivateJWTClientKeyEndpoint(t *testing.T) {
	t.Parallel()

	provider, err := core.NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}
	privateKey1 := mustGenerateTestPrivateKeyPEM(t)
	if err := provider.RegisterPrivateJWTClient(
		core.DefaultPrivateJWTClientID,
		core.DefaultPrivateJWTRedirect,
		mustPublicKeyPEMFromPrivateKey(t, privateKey1),
	); err != nil {
		t.Fatalf("RegisterPrivateJWTClient error: %v", err)
	}
	h := NewHandlerWithPrivateJWTClientKeyRotation(provider, "test-private-jwt-rotation-token")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	methodReq := httptest.NewRequest(http.MethodGet, "/oauth2/admin/rotate-private-jwt-client-key", nil)
	methodRec := httptest.NewRecorder()
	mux.ServeHTTP(methodRec, methodReq)
	if methodRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method check failed: got=%d want=%d", methodRec.Code, http.StatusMethodNotAllowed)
	}

	missingAuthReq := httptest.NewRequest(http.MethodPost, "/oauth2/admin/rotate-private-jwt-client-key", strings.NewReader("{}"))
	missingAuthRec := httptest.NewRecorder()
	mux.ServeHTTP(missingAuthRec, missingAuthReq)
	if missingAuthRec.Code != http.StatusUnauthorized {
		t.Fatalf("missing auth must be rejected: got=%d want=%d", missingAuthRec.Code, http.StatusUnauthorized)
	}

	invalidTokenReq := httptest.NewRequest(http.MethodPost, "/oauth2/admin/rotate-private-jwt-client-key", strings.NewReader("{}"))
	invalidTokenReq.Header.Set("Authorization", "Bearer wrong-token")
	invalidTokenRec := httptest.NewRecorder()
	mux.ServeHTTP(invalidTokenRec, invalidTokenReq)
	if invalidTokenRec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token must be rejected: got=%d want=%d", invalidTokenRec.Code, http.StatusUnauthorized)
	}

	invalidJSONReq := httptest.NewRequest(http.MethodPost, "/oauth2/admin/rotate-private-jwt-client-key", strings.NewReader("{"))
	invalidJSONReq.Header.Set("Authorization", "Bearer test-private-jwt-rotation-token")
	invalidJSONReq.Header.Set("Content-Type", "application/json")
	invalidJSONRec := httptest.NewRecorder()
	mux.ServeHTTP(invalidJSONRec, invalidJSONReq)
	if invalidJSONRec.Code != http.StatusBadRequest {
		t.Fatalf("invalid json must be rejected: got=%d want=%d", invalidJSONRec.Code, http.StatusBadRequest)
	}

	privateKey2 := mustGenerateTestPrivateKeyPEM(t)
	rotatePayload := map[string]string{
		"client_id":      core.DefaultPrivateJWTClientID,
		"public_key_pem": mustPublicKeyPEMFromPrivateKey(t, privateKey2),
	}
	body, err := json.Marshal(rotatePayload)
	if err != nil {
		t.Fatalf("marshal rotate payload error: %v", err)
	}

	rotateReq := httptest.NewRequest(http.MethodPost, "/oauth2/admin/rotate-private-jwt-client-key", strings.NewReader(string(body)))
	rotateReq.Header.Set("Authorization", "Bearer test-private-jwt-rotation-token")
	rotateReq.Header.Set("Content-Type", "application/json")
	rotateRec := httptest.NewRecorder()
	mux.ServeHTTP(rotateRec, rotateReq)
	if rotateRec.Code != http.StatusOK {
		t.Fatalf("rotate private_jwt client key request failed: got=%d want=%d", rotateRec.Code, http.StatusOK)
	}

	var rotateResp map[string]string
	if err := json.Unmarshal(rotateRec.Body.Bytes(), &rotateResp); err != nil {
		t.Fatalf("rotate response json error: %v", err)
	}
	if rotateResp["kid"] == "" {
		t.Fatalf("rotate response must include kid")
	}

	assertPrivateJWTClientAuthentication(t, provider, privateKey2)
	assertPrivateJWTClientAuthentication(t, provider, privateKey1)
}

func TestRotatePrivateJWTClientKeyEndpointWithoutTokenConfig(t *testing.T) {
	t.Parallel()

	provider, err := core.NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}
	privateKey := mustGenerateTestPrivateKeyPEM(t)
	if err := provider.RegisterPrivateJWTClient(
		core.DefaultPrivateJWTClientID,
		core.DefaultPrivateJWTRedirect,
		mustPublicKeyPEMFromPrivateKey(t, privateKey),
	); err != nil {
		t.Fatalf("RegisterPrivateJWTClient error: %v", err)
	}
	h := NewHandlerWithPrivateJWTClientKeyRotation(provider, "   ")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/admin/rotate-private-jwt-client-key", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer any-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("misconfigured token must return 500: got=%d want=%d", rec.Code, http.StatusInternalServerError)
	}
}

func TestRotatePrivateJWTClientKeyEndpointWithJWTAdminAuth(t *testing.T) {
	t.Parallel()

	provider, err := core.NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}
	privateKey := mustGenerateTestPrivateKeyPEM(t)
	if err := provider.RegisterPrivateJWTClient(
		core.DefaultPrivateJWTClientID,
		core.DefaultPrivateJWTRedirect,
		mustPublicKeyPEMFromPrivateKey(t, privateKey),
	); err != nil {
		t.Fatalf("RegisterPrivateJWTClient error: %v", err)
	}
	h := NewHandlerWithPrivateJWTClientKeyRotationAuth(
		provider,
		"unused-static-token",
		middleware.AdminAuthModeJWT,
		"test-private-admin-jwt-secret",
		"test-admin-issuer",
		"oidc-admin",
	)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	invalidScopeToken := signAdminJWT(
		t,
		"test-private-admin-jwt-secret",
		map[string]any{
			"iss":   "test-admin-issuer",
			"aud":   "oidc-admin",
			"exp":   time.Now().UTC().Add(5 * time.Minute).Unix(),
			"scope": middleware.ScopeRotateSigningKey,
		},
	)
	invalidScopeReq := httptest.NewRequest(http.MethodPost, "/oauth2/admin/rotate-private-jwt-client-key", strings.NewReader("{}"))
	invalidScopeReq.Header.Set("Authorization", "Bearer "+invalidScopeToken)
	invalidScopeReq.Header.Set("Content-Type", "application/json")
	invalidScopeRec := httptest.NewRecorder()
	mux.ServeHTTP(invalidScopeRec, invalidScopeReq)
	if invalidScopeRec.Code != http.StatusForbidden {
		t.Fatalf("insufficient scope must be rejected: got=%d want=%d", invalidScopeRec.Code, http.StatusForbidden)
	}

	privateKey2 := mustGenerateTestPrivateKeyPEM(t)
	body, err := json.Marshal(map[string]string{
		"client_id":      core.DefaultPrivateJWTClientID,
		"public_key_pem": mustPublicKeyPEMFromPrivateKey(t, privateKey2),
	})
	if err != nil {
		t.Fatalf("marshal rotate payload error: %v", err)
	}
	validToken := signAdminJWT(
		t,
		"test-private-admin-jwt-secret",
		map[string]any{
			"iss":   "test-admin-issuer",
			"aud":   "oidc-admin",
			"exp":   time.Now().UTC().Add(5 * time.Minute).Unix(),
			"scope": middleware.ScopeRotatePrivateJWTClientKey,
		},
	)
	validReq := httptest.NewRequest(http.MethodPost, "/oauth2/admin/rotate-private-jwt-client-key", strings.NewReader(string(body)))
	validReq.Header.Set("Authorization", "Bearer "+validToken)
	validReq.Header.Set("Content-Type", "application/json")
	validRec := httptest.NewRecorder()
	mux.ServeHTTP(validRec, validReq)
	if validRec.Code != http.StatusOK {
		t.Fatalf("valid jwt scope must be accepted: got=%d want=%d", validRec.Code, http.StatusOK)
	}
}

func signAdminJWT(t *testing.T, secret string, claims map[string]any) string {
	t.Helper()

	signedClaims := map[string]any{}
	for k, v := range claims {
		signedClaims[k] = v
	}
	if _, ok := signedClaims["jti"]; !ok {
		signedClaims["jti"] = fmt.Sprintf("admin-jti-%d", time.Now().UTC().UnixNano())
	}

	headerBytes, err := json.Marshal(map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	})
	if err != nil {
		t.Fatalf("marshal header error: %v", err)
	}
	claimsBytes, err := json.Marshal(signedClaims)
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

func assertTokenErrorContract(t *testing.T, rec *httptest.ResponseRecorder, expectedStatus int, expectedError string) {
	t.Helper()

	if rec.Code != expectedStatus {
		t.Fatalf("unexpected status: got=%d want=%d body=%s", rec.Code, expectedStatus, rec.Body.String())
	}
	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid token error json: %v", err)
	}
	if payload["error"] != expectedError {
		t.Fatalf("unexpected oauth error: got=%s want=%s", payload["error"], expectedError)
	}
	desc := strings.TrimSpace(payload["error_description"])
	if desc == "" {
		t.Fatalf("error_description must not be empty")
	}
	lowerDesc := strings.ToLower(desc)
	if strings.Contains(lowerDesc, "panic") || strings.Contains(lowerDesc, "stack") || strings.Contains(lowerDesc, "internal") {
		t.Fatalf("error_description must not expose internal details: %s", desc)
	}
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

func assertPrivateJWTClientAuthentication(t *testing.T, provider *core.Provider, privateKeyPEM string) {
	t.Helper()

	assertion := signClientAssertion(
		t,
		privateKeyPEM,
		core.DefaultPrivateJWTClientID,
		testIssuer+"/oauth2/token",
		time.Now().UTC().Add(5*time.Minute),
	)
	if err := provider.AuthenticateTokenClient(core.TokenClientAuthentication{
		ClientID:            core.DefaultPrivateJWTClientID,
		AuthMethod:          core.TokenEndpointAuthMethodPrivate,
		ClientAssertionType: core.ClientAssertionTypeJWTBearer,
		ClientAssertion:     assertion,
	}); err != nil {
		t.Fatalf("private_key_jwt client authentication must succeed: %v", err)
	}
}

func mustGenerateTestPrivateKeyPEM(t *testing.T) string {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa private key error: %v", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal pkcs8 private key error: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	}))
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

func mustPublicKeyPEMFromPrivateKey(t *testing.T, privateKeyPEM string) string {
	t.Helper()

	privateKey := parseRSAPrivateKey(t, privateKeyPEM)
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal rsa public key error: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}))
}
