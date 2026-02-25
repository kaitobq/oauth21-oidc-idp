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
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	testIssuer       = "http://localhost:8080"
	testClientID     = "test-client"
	testRedirectURI  = "http://localhost:3000/callback"
	testCodeVerifier = "this-is-a-long-enough-code-verifier-for-tests-123456789"
	testNonce        = "nonce-provider-test-123"
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
	if !contains(d.ACRValuesSupported, defaultACRValue) {
		t.Fatalf("acr_values_supported must include %s", defaultACRValue)
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
	if !contains(d.TokenEndpointAuthMethodsSupported, "client_secret_basic") {
		t.Fatalf("token_endpoint_auth_methods_supported must include client_secret_basic")
	}
	if contains(d.TokenEndpointAuthMethodsSupported, "private_key_jwt") {
		t.Fatalf("token_endpoint_auth_methods_supported must not include private_key_jwt without client registration")
	}

	if err := provider.RegisterPrivateJWTClient(
		DefaultPrivateJWTClientID,
		DefaultPrivateJWTRedirect,
		mustPublicKeyPEMFromPrivateKey(t, testPrivateJWTClientPrivateKeyPEM),
	); err != nil {
		t.Fatalf("RegisterPrivateJWTClient error: %v", err)
	}
	d = provider.Discovery()
	if !contains(d.TokenEndpointAuthMethodsSupported, "private_key_jwt") {
		t.Fatalf("token_endpoint_auth_methods_supported must include private_key_jwt after client registration")
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
		defaultACRValue,
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
	if claims["azp"] != testClientID {
		t.Fatalf("id_token azp mismatch: %v", claims["azp"])
	}
	if sid, ok := claims["sid"].(string); !ok || sid == "" {
		t.Fatalf("id_token must include non-empty sid")
	}
	if _, ok := claims["auth_time"].(float64); !ok {
		t.Fatalf("id_token must include numeric auth_time")
	}
	if claims["acr"] != defaultACRValue {
		t.Fatalf("id_token acr mismatch: %v", claims["acr"])
	}
	if !claimHasStringValue(t, claims, "amr", defaultAMRMethod) {
		t.Fatalf("id_token amr must include %s", defaultAMRMethod)
	}
	if claims["at_hash"] != accessTokenHash(tokenResp.AccessToken) {
		t.Fatalf("id_token at_hash mismatch: %v", claims["at_hash"])
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

func TestAuthenticateTokenClient(t *testing.T) {
	t.Parallel()

	provider, err := NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}

	if err := provider.AuthenticateTokenClient(TokenClientAuthentication{
		ClientID:   testClientID,
		AuthMethod: TokenEndpointAuthMethodNone,
	}); err != nil {
		t.Fatalf("public client authentication must succeed: %v", err)
	}

	if err := provider.AuthenticateTokenClient(TokenClientAuthentication{
		ClientID:     DefaultConfidentialClientID,
		AuthMethod:   TokenEndpointAuthMethodBasic,
		ClientSecret: DefaultConfidentialClientSecret,
	}); err != nil {
		t.Fatalf("confidential client authentication must succeed: %v", err)
	}

	if err := provider.RegisterPrivateJWTClient(
		DefaultPrivateJWTClientID,
		DefaultPrivateJWTRedirect,
		mustPublicKeyPEMFromPrivateKey(t, testPrivateJWTClientPrivateKeyPEM),
	); err != nil {
		t.Fatalf("RegisterPrivateJWTClient error: %v", err)
	}

	validAssertion := signClientAssertion(
		t,
		testPrivateJWTClientPrivateKeyPEM,
		DefaultPrivateJWTClientID,
		testIssuer+"/oauth2/token",
		time.Now().UTC().Add(5*time.Minute),
	)
	if err := provider.AuthenticateTokenClient(TokenClientAuthentication{
		ClientID:            DefaultPrivateJWTClientID,
		AuthMethod:          TokenEndpointAuthMethodPrivate,
		ClientAssertionType: ClientAssertionTypeJWTBearer,
		ClientAssertion:     validAssertion,
	}); err != nil {
		t.Fatalf("private_key_jwt client authentication must succeed: %v", err)
	}

	invalidSecretErr := provider.AuthenticateTokenClient(TokenClientAuthentication{
		ClientID:     DefaultConfidentialClientID,
		AuthMethod:   TokenEndpointAuthMethodBasic,
		ClientSecret: "wrong-secret",
	})
	assertOAuthError(t, invalidSecretErr, "invalid_client")

	wrongMethodErr := provider.AuthenticateTokenClient(TokenClientAuthentication{
		ClientID:   DefaultConfidentialClientID,
		AuthMethod: TokenEndpointAuthMethodNone,
	})
	assertOAuthError(t, wrongMethodErr, "invalid_client")

	expiredAssertionErr := provider.AuthenticateTokenClient(TokenClientAuthentication{
		ClientID:            DefaultPrivateJWTClientID,
		AuthMethod:          TokenEndpointAuthMethodPrivate,
		ClientAssertionType: ClientAssertionTypeJWTBearer,
		ClientAssertion: signClientAssertion(
			t,
			testPrivateJWTClientPrivateKeyPEM,
			DefaultPrivateJWTClientID,
			testIssuer+"/oauth2/token",
			time.Now().UTC().Add(-5*time.Minute),
		),
	})
	assertOAuthError(t, expiredAssertionErr, "invalid_client")
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
		defaultACRValue,
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
	if firstClaims["azp"] != testClientID {
		t.Fatalf("first id_token azp mismatch: %v", firstClaims["azp"])
	}
	sid, ok := firstClaims["sid"].(string)
	if !ok || sid == "" {
		t.Fatalf("first id_token must include non-empty sid")
	}
	authTime, ok := firstClaims["auth_time"].(float64)
	if !ok {
		t.Fatalf("first id_token must include numeric auth_time")
	}
	if firstClaims["acr"] != defaultACRValue {
		t.Fatalf("first id_token acr mismatch: %v", firstClaims["acr"])
	}
	if !claimHasStringValue(t, firstClaims, "amr", defaultAMRMethod) {
		t.Fatalf("first id_token amr must include %s", defaultAMRMethod)
	}
	if firstClaims["at_hash"] != accessTokenHash(firstTokenResp.AccessToken) {
		t.Fatalf("first id_token at_hash mismatch: %v", firstClaims["at_hash"])
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
	if secondClaims["azp"] != testClientID {
		t.Fatalf("refresh id_token azp mismatch: %v", secondClaims["azp"])
	}
	if secondClaims["sid"] != sid {
		t.Fatalf("refresh id_token sid mismatch: got=%v want=%v", secondClaims["sid"], sid)
	}
	if secondClaims["auth_time"] != authTime {
		t.Fatalf("refresh id_token auth_time mismatch: got=%v want=%v", secondClaims["auth_time"], authTime)
	}
	if secondClaims["acr"] != defaultACRValue {
		t.Fatalf("refresh id_token acr mismatch: %v", secondClaims["acr"])
	}
	if !claimHasStringValue(t, secondClaims, "amr", defaultAMRMethod) {
		t.Fatalf("refresh id_token amr must include %s", defaultAMRMethod)
	}
	if secondClaims["at_hash"] != accessTokenHash(secondTokenResp.AccessToken) {
		t.Fatalf("refresh id_token at_hash mismatch: %v", secondClaims["at_hash"])
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

func TestAuthorizeRejectUnsupportedACRValues(t *testing.T) {
	t.Parallel()

	provider, err := NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}

	_, err = provider.Authorize(
		"code",
		testClientID,
		testRedirectURI,
		"openid",
		"state-acr",
		"",
		"urn:unsupported:acr",
		pkceS256(testCodeVerifier),
		"S256",
	)
	if err == nil {
		t.Fatalf("authorize with unsupported acr_values must fail")
	}
	assertOAuthError(t, err, "invalid_request")
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
