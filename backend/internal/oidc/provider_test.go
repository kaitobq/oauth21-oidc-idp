package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

const (
	testIssuer       = "http://localhost:8080"
	testClientID     = "test-client"
	testRedirectURI  = "http://localhost:3000/callback"
	testCodeVerifier = "this-is-a-long-enough-code-verifier-for-tests-123456789"
	testNonce        = "nonce-provider-test-123"
)

func TestProviderDiscoveryAndJWKS(t *testing.T) {
	t.Parallel()

	provider, err := NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}

	d := provider.Discovery()
	if d.Issuer != testIssuer {
		t.Fatalf("unexpected issuer: %s", d.Issuer)
	}
	if d.JWKSURI == "" {
		t.Fatalf("jwks_uri must not be empty")
	}

	if contains(d.GrantTypesSupported, "password") {
		t.Fatalf("grant_types_supported must not include password")
	}
	if !contains(d.GrantTypesSupported, "authorization_code") {
		t.Fatalf("grant_types_supported must include authorization_code")
	}
	if !contains(d.GrantTypesSupported, "refresh_token") {
		t.Fatalf("grant_types_supported must include refresh_token")
	}
	if !contains(d.CodeChallengeMethodsSupported, "S256") {
		t.Fatalf("code_challenge_methods_supported must include S256")
	}
	if !contains(d.ScopesSupported, "openid") {
		t.Fatalf("scopes_supported must include openid")
	}
	if !contains(d.ScopesSupported, "offline_access") {
		t.Fatalf("scopes_supported must include offline_access")
	}
	if !contains(d.TokenEndpointAuthMethodsSupported, "none") {
		t.Fatalf("token_endpoint_auth_methods_supported must include none")
	}

	ks := provider.JWKS()
	if len(ks.Keys) == 0 {
		t.Fatalf("jwks keys must not be empty")
	}
	if ks.Keys[0].N == "" || ks.Keys[0].E == "" {
		t.Fatalf("jwk modulus/exponent must not be empty")
	}
}

func TestAuthorizeAndExchangeAuthorizationCodeSuccess(t *testing.T) {
	t.Parallel()

	provider, err := NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}

	redirectURL, err := provider.Authorize(
		"code",
		testClientID,
		testRedirectURI,
		"openid profile",
		"state-1",
		testNonce,
		pkceS256(testCodeVerifier),
		"S256",
	)
	if err != nil {
		t.Fatalf("Authorize error: %v", err)
	}

	code := queryParam(t, redirectURL, "code")
	if code == "" {
		t.Fatalf("authorization code must not be empty")
	}
	if gotState := queryParam(t, redirectURL, "state"); gotState != "state-1" {
		t.Fatalf("unexpected state: %s", gotState)
	}

	tokenResp, err := provider.ExchangeAuthorizationCode(
		"authorization_code",
		code,
		testRedirectURI,
		testClientID,
		testCodeVerifier,
	)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode error: %v", err)
	}
	if tokenResp.AccessToken == "" {
		t.Fatalf("access token must not be empty")
	}
	if tokenResp.TokenType != "Bearer" {
		t.Fatalf("unexpected token_type: %s", tokenResp.TokenType)
	}
	if tokenResp.ExpiresIn <= 0 {
		t.Fatalf("expires_in must be positive")
	}
	if tokenResp.IDToken == "" {
		t.Fatalf("id_token must be returned for openid scope")
	}
	if tokenResp.RefreshToken != "" {
		t.Fatalf("refresh_token must not be returned without offline_access scope")
	}
	claims := parseJWTClaims(t, tokenResp.IDToken)
	if claims["nonce"] != testNonce {
		t.Fatalf("id_token nonce mismatch: %v", claims["nonce"])
	}
	if _, ok := claims["auth_time"].(float64); !ok {
		t.Fatalf("id_token must include numeric auth_time")
	}
}

func TestExchangeAuthorizationCodeRejectReuse(t *testing.T) {
	t.Parallel()

	provider, err := NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}

	redirectURL, err := provider.Authorize(
		"code",
		testClientID,
		testRedirectURI,
		"openid",
		"state-reuse",
		"",
		pkceS256(testCodeVerifier),
		"S256",
	)
	if err != nil {
		t.Fatalf("Authorize error: %v", err)
	}
	code := queryParam(t, redirectURL, "code")

	_, err = provider.ExchangeAuthorizationCode(
		"authorization_code",
		code,
		testRedirectURI,
		testClientID,
		testCodeVerifier,
	)
	if err != nil {
		t.Fatalf("first ExchangeAuthorizationCode error: %v", err)
	}

	_, err = provider.ExchangeAuthorizationCode(
		"authorization_code",
		code,
		testRedirectURI,
		testClientID,
		testCodeVerifier,
	)
	if err == nil {
		t.Fatalf("second exchange must fail")
	}
	assertOAuthError(t, err, "invalid_grant")
}

func TestExchangeAuthorizationCodeRejectVerifierMismatch(t *testing.T) {
	t.Parallel()

	provider, err := NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}

	redirectURL, err := provider.Authorize(
		"code",
		testClientID,
		testRedirectURI,
		"openid",
		"state-mismatch",
		"",
		pkceS256(testCodeVerifier),
		"S256",
	)
	if err != nil {
		t.Fatalf("Authorize error: %v", err)
	}
	code := queryParam(t, redirectURL, "code")

	_, err = provider.ExchangeAuthorizationCode(
		"authorization_code",
		code,
		testRedirectURI,
		testClientID,
		"wrong-code-verifier",
	)
	if err == nil {
		t.Fatalf("exchange must fail on verifier mismatch")
	}
	assertOAuthError(t, err, "invalid_grant")
}

func TestRefreshTokenRotation(t *testing.T) {
	t.Parallel()

	provider, err := NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}

	redirectURL, err := provider.Authorize(
		"code",
		testClientID,
		testRedirectURI,
		"openid offline_access",
		"state-refresh",
		testNonce,
		pkceS256(testCodeVerifier),
		"S256",
	)
	if err != nil {
		t.Fatalf("Authorize error: %v", err)
	}
	code := queryParam(t, redirectURL, "code")

	firstTokenResp, err := provider.ExchangeAuthorizationCode(
		"authorization_code",
		code,
		testRedirectURI,
		testClientID,
		testCodeVerifier,
	)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode error: %v", err)
	}
	if firstTokenResp.RefreshToken == "" {
		t.Fatalf("refresh_token must be returned for offline_access scope")
	}
	firstClaims := parseJWTClaims(t, firstTokenResp.IDToken)
	if firstClaims["nonce"] != testNonce {
		t.Fatalf("first id_token nonce mismatch: %v", firstClaims["nonce"])
	}
	authTime, ok := firstClaims["auth_time"].(float64)
	if !ok {
		t.Fatalf("first id_token must include numeric auth_time")
	}

	secondTokenResp, err := provider.ExchangeRefreshToken(
		"refresh_token",
		firstTokenResp.RefreshToken,
		testClientID,
		"",
	)
	if err != nil {
		t.Fatalf("ExchangeRefreshToken error: %v", err)
	}
	if secondTokenResp.AccessToken == "" {
		t.Fatalf("refresh exchange must issue access_token")
	}
	if secondTokenResp.RefreshToken == "" {
		t.Fatalf("refresh exchange must rotate refresh_token")
	}
	if secondTokenResp.RefreshToken == firstTokenResp.RefreshToken {
		t.Fatalf("refresh_token must be rotated")
	}
	secondClaims := parseJWTClaims(t, secondTokenResp.IDToken)
	if _, ok := secondClaims["nonce"]; ok {
		t.Fatalf("refresh id_token must not include nonce")
	}
	if secondClaims["auth_time"] != authTime {
		t.Fatalf("refresh id_token auth_time mismatch: got=%v want=%v", secondClaims["auth_time"], authTime)
	}

	_, err = provider.ExchangeRefreshToken(
		"refresh_token",
		firstTokenResp.RefreshToken,
		testClientID,
		"",
	)
	if err == nil {
		t.Fatalf("reusing refresh token must fail")
	}
	assertOAuthError(t, err, "invalid_grant")
}

func TestRefreshTokenRejectInvalidScope(t *testing.T) {
	t.Parallel()

	provider, err := NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}

	redirectURL, err := provider.Authorize(
		"code",
		testClientID,
		testRedirectURI,
		"openid offline_access",
		"state-refresh-scope",
		"",
		pkceS256(testCodeVerifier),
		"S256",
	)
	if err != nil {
		t.Fatalf("Authorize error: %v", err)
	}
	code := queryParam(t, redirectURL, "code")

	firstTokenResp, err := provider.ExchangeAuthorizationCode(
		"authorization_code",
		code,
		testRedirectURI,
		testClientID,
		testCodeVerifier,
	)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode error: %v", err)
	}

	_, err = provider.ExchangeRefreshToken(
		"refresh_token",
		firstTokenResp.RefreshToken,
		testClientID,
		"openid offline_access email",
	)
	if err == nil {
		t.Fatalf("refresh exchange with scope escalation must fail")
	}
	assertOAuthError(t, err, "invalid_scope")
}

func assertOAuthError(t *testing.T, err error, code string) {
	t.Helper()

	oauthErr, ok := err.(*OAuthError)
	if !ok {
		t.Fatalf("expected OAuthError, got %T", err)
	}
	if oauthErr.Code != code {
		t.Fatalf("unexpected oauth error code: %s", oauthErr.Code)
	}
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

func contains(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}
