package oidc

import (
	"context"
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

func TestProviderDiscoveryAndJWKS(t *testing.T) {
	t.Parallel()

	provider, err := NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}
	privateKeyPEM := mustGenerateTestPrivateKeyPEM(t)

	d := provider.Discovery()
	if d.Issuer != testIssuer {
		t.Fatalf("unexpected issuer: %s", d.Issuer)
	}
	if d.JWKSURI == "" {
		t.Fatalf("jwks_uri must not be empty")
	}
	if d.UserInfoEndpoint == "" {
		t.Fatalf("userinfo_endpoint must not be empty")
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
		mustPublicKeyPEMFromPrivateKey(t, privateKeyPEM),
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

func TestRotateSigningKey(t *testing.T) {
	t.Parallel()

	provider, err := NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}

	initialJWKS := provider.JWKS()
	if len(initialJWKS.Keys) != 1 {
		t.Fatalf("initial jwks must contain one key")
	}
	initialKID := initialJWKS.Keys[0].Kid
	if initialKID == "" {
		t.Fatalf("initial kid must not be empty")
	}

	issueIDToken := func(state string) string {
		redirectURL, err := provider.Authorize(
			"code",
			testClientID,
			testRedirectURI,
			"openid",
			state,
			"",
			"",
			pkceS256(testCodeVerifier),
			"S256",
		)
		if err != nil {
			t.Fatalf("Authorize error: %v", err)
		}
		code := queryParam(t, redirectURL, "code")
		resp, err := provider.ExchangeAuthorizationCode(
			"authorization_code",
			code,
			testRedirectURI,
			testClientID,
			testCodeVerifier,
		)
		if err != nil {
			t.Fatalf("ExchangeAuthorizationCode error: %v", err)
		}
		return resp.IDToken
	}

	firstHeader := parseJWTHeader(t, issueIDToken("state-before-rotate"))
	if firstHeader["kid"] != initialKID {
		t.Fatalf("first id_token kid mismatch: got=%v want=%v", firstHeader["kid"], initialKID)
	}

	rotatedKID, err := provider.RotateSigningKey()
	if err != nil {
		t.Fatalf("RotateSigningKey error: %v", err)
	}
	if rotatedKID == initialKID {
		t.Fatalf("rotated kid must differ from initial kid")
	}

	afterFirstRotate := provider.JWKS()
	if len(afterFirstRotate.Keys) != defaultMaxPublishedSigningKeys {
		t.Fatalf("jwks key count after first rotation mismatch: got=%d want=%d", len(afterFirstRotate.Keys), defaultMaxPublishedSigningKeys)
	}
	if afterFirstRotate.Keys[0].Kid != rotatedKID {
		t.Fatalf("active jwks kid mismatch after first rotation: got=%s want=%s", afterFirstRotate.Keys[0].Kid, rotatedKID)
	}
	if !jwksContainsKID(afterFirstRotate, initialKID) {
		t.Fatalf("jwks must retain previous key after first rotation")
	}

	secondHeader := parseJWTHeader(t, issueIDToken("state-after-first-rotate"))
	if secondHeader["kid"] != rotatedKID {
		t.Fatalf("id_token kid mismatch after first rotation: got=%v want=%v", secondHeader["kid"], rotatedKID)
	}

	secondRotatedKID, err := provider.RotateSigningKey()
	if err != nil {
		t.Fatalf("second RotateSigningKey error: %v", err)
	}
	if secondRotatedKID == rotatedKID {
		t.Fatalf("second rotated kid must differ from previous rotated kid")
	}

	afterSecondRotate := provider.JWKS()
	if len(afterSecondRotate.Keys) != defaultMaxPublishedSigningKeys {
		t.Fatalf("jwks key count after second rotation mismatch: got=%d want=%d", len(afterSecondRotate.Keys), defaultMaxPublishedSigningKeys)
	}
	if afterSecondRotate.Keys[0].Kid != secondRotatedKID {
		t.Fatalf("active jwks kid mismatch after second rotation: got=%s want=%s", afterSecondRotate.Keys[0].Kid, secondRotatedKID)
	}
	if !jwksContainsKID(afterSecondRotate, rotatedKID) {
		t.Fatalf("jwks must retain previous active key after second rotation")
	}
	if jwksContainsKID(afterSecondRotate, initialKID) {
		t.Fatalf("oldest key must be removed after exceeding max published keys")
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
	privateKeyPEM := mustGenerateTestPrivateKeyPEM(t)

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
		mustPublicKeyPEMFromPrivateKey(t, privateKeyPEM),
	); err != nil {
		t.Fatalf("RegisterPrivateJWTClient error: %v", err)
	}

	validAssertion := signClientAssertion(
		t,
		privateKeyPEM,
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
	replayAssertionErr := provider.AuthenticateTokenClient(TokenClientAuthentication{
		ClientID:            DefaultPrivateJWTClientID,
		AuthMethod:          TokenEndpointAuthMethodPrivate,
		ClientAssertionType: ClientAssertionTypeJWTBearer,
		ClientAssertion:     validAssertion,
	})
	assertOAuthError(t, replayAssertionErr, "invalid_client")

	missingJTIAssertionErr := provider.AuthenticateTokenClient(TokenClientAuthentication{
		ClientID:            DefaultPrivateJWTClientID,
		AuthMethod:          TokenEndpointAuthMethodPrivate,
		ClientAssertionType: ClientAssertionTypeJWTBearer,
		ClientAssertion: signClientAssertionWithoutJTI(
			t,
			privateKeyPEM,
			DefaultPrivateJWTClientID,
			testIssuer+"/oauth2/token",
			time.Now().UTC().Add(5*time.Minute),
		),
	})
	assertOAuthError(t, missingJTIAssertionErr, "invalid_client")

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
			privateKeyPEM,
			DefaultPrivateJWTClientID,
			testIssuer+"/oauth2/token",
			time.Now().UTC().Add(-5*time.Minute),
		),
	})
	assertOAuthError(t, expiredAssertionErr, "invalid_client")
}

func TestRotatePrivateJWTClientKey(t *testing.T) {
	t.Parallel()

	provider, err := NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}

	privateKey1 := mustGenerateTestPrivateKeyPEM(t)
	if err := provider.RegisterPrivateJWTClient(
		DefaultPrivateJWTClientID,
		DefaultPrivateJWTRedirect,
		mustPublicKeyPEMFromPrivateKey(t, privateKey1),
	); err != nil {
		t.Fatalf("RegisterPrivateJWTClient error: %v", err)
	}

	assertPrivateJWTClientAuthentication(t, provider, privateKey1)

	privateKey2 := mustGenerateTestPrivateKeyPEM(t)
	kid2, err := provider.RotatePrivateJWTClientKey(
		DefaultPrivateJWTClientID,
		mustPublicKeyPEMFromPrivateKey(t, privateKey2),
	)
	if err != nil {
		t.Fatalf("RotatePrivateJWTClientKey first rotation error: %v", err)
	}
	if kid2 == "" {
		t.Fatalf("first rotated kid must not be empty")
	}

	assertPrivateJWTClientAuthentication(t, provider, privateKey2)
	assertPrivateJWTClientAuthentication(t, provider, privateKey1)

	privateKey3 := mustGenerateTestPrivateKeyPEM(t)
	kid3, err := provider.RotatePrivateJWTClientKey(
		DefaultPrivateJWTClientID,
		mustPublicKeyPEMFromPrivateKey(t, privateKey3),
	)
	if err != nil {
		t.Fatalf("RotatePrivateJWTClientKey second rotation error: %v", err)
	}
	if kid3 == "" {
		t.Fatalf("second rotated kid must not be empty")
	}
	if kid3 == kid2 {
		t.Fatalf("second rotated kid must differ from previous rotated kid")
	}

	assertPrivateJWTClientAuthentication(t, provider, privateKey3)
	assertPrivateJWTClientAuthentication(t, provider, privateKey2)

	evictedKeyAssertion := signClientAssertion(
		t,
		privateKey1,
		DefaultPrivateJWTClientID,
		testIssuer+"/oauth2/token",
		time.Now().UTC().Add(5*time.Minute),
	)
	evictedKeyErr := provider.AuthenticateTokenClient(TokenClientAuthentication{
		ClientID:            DefaultPrivateJWTClientID,
		AuthMethod:          TokenEndpointAuthMethodPrivate,
		ClientAssertionType: ClientAssertionTypeJWTBearer,
		ClientAssertion:     evictedKeyAssertion,
	})
	assertOAuthError(t, evictedKeyErr, "invalid_client")
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

func TestUserInfo(t *testing.T) {
	t.Parallel()

	provider, err := NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}

	redirectURL, err := provider.Authorize(
		"code",
		testClientID,
		testRedirectURI,
		"openid profile email",
		"state-userinfo",
		"",
		"",
		pkceS256(testCodeVerifier),
		"S256",
	)
	if err != nil {
		t.Fatalf("Authorize error: %v", err)
	}
	code := queryParam(t, redirectURL, "code")

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

	userInfo, err := provider.UserInfo(tokenResp.AccessToken)
	if err != nil {
		t.Fatalf("UserInfo error: %v", err)
	}
	if userInfo.Sub == "" {
		t.Fatalf("userinfo sub must not be empty")
	}
	if userInfo.Name == "" {
		t.Fatalf("userinfo name must not be empty with profile scope")
	}
	if userInfo.Email == "" || !userInfo.EmailVerified {
		t.Fatalf("userinfo email claims must be present with email scope")
	}
}

func TestUserInfoRejectInvalidTokenAndInsufficientScope(t *testing.T) {
	t.Parallel()

	provider, err := NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}

	_, err = provider.UserInfo("invalid-token")
	if err == nil {
		t.Fatalf("UserInfo with invalid token must fail")
	}
	assertOAuthError(t, err, "invalid_token")

	redirectURL, err := provider.Authorize(
		"code",
		testClientID,
		testRedirectURI,
		"profile",
		"state-userinfo-no-openid",
		"",
		"",
		pkceS256(testCodeVerifier),
		"S256",
	)
	if err != nil {
		t.Fatalf("Authorize error: %v", err)
	}
	code := queryParam(t, redirectURL, "code")

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

	_, err = provider.UserInfo(tokenResp.AccessToken)
	if err == nil {
		t.Fatalf("UserInfo without openid scope must fail")
	}
	assertOAuthError(t, err, "insufficient_scope")
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

func TestConfigureClientStoreLoadsClients(t *testing.T) {
	t.Parallel()

	provider, err := NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}

	privateKeyPEM := mustGenerateTestPrivateKeyPEM(t)
	store := &mockClientStore{
		loaded: []ClientSnapshot{
			{
				ID:                      "persisted-basic-client",
				RedirectURIs:            []string{"http://localhost:3000/basic-callback"},
				TokenEndpointAuthMethod: TokenEndpointAuthMethodBasic,
				ClientSecret:            "persisted-basic-secret",
			},
			{
				ID:                      "persisted-private-client",
				RedirectURIs:            []string{"http://localhost:3000/private-callback"},
				TokenEndpointAuthMethod: TokenEndpointAuthMethodPrivate,
				JWTSigningPublicKeysPEM: []string{mustPublicKeyPEMFromPrivateKey(t, privateKeyPEM)},
			},
		},
	}

	if err := provider.ConfigureClientStore(context.Background(), store); err != nil {
		t.Fatalf("ConfigureClientStore error: %v", err)
	}
	if len(store.saved) == 0 {
		t.Fatalf("client store must be persisted at least once")
	}

	if err := provider.AuthenticateTokenClient(TokenClientAuthentication{
		ClientID:     "persisted-basic-client",
		AuthMethod:   TokenEndpointAuthMethodBasic,
		ClientSecret: "persisted-basic-secret",
	}); err != nil {
		t.Fatalf("persisted basic client auth must succeed: %v", err)
	}

	assertion := signClientAssertion(
		t,
		privateKeyPEM,
		"persisted-private-client",
		testIssuer+"/oauth2/token",
		time.Now().UTC().Add(5*time.Minute),
	)
	if err := provider.AuthenticateTokenClient(TokenClientAuthentication{
		ClientID:            "persisted-private-client",
		AuthMethod:          TokenEndpointAuthMethodPrivate,
		ClientAssertionType: ClientAssertionTypeJWTBearer,
		ClientAssertion:     assertion,
	}); err != nil {
		t.Fatalf("persisted private_key_jwt client auth must succeed: %v", err)
	}
}

func TestClientStoreSaveFailureRollsBackRegistration(t *testing.T) {
	t.Parallel()

	provider, err := NewProvider(testIssuer, testClientID, testRedirectURI)
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}
	store := &mockClientStore{}
	if err := provider.ConfigureClientStore(context.Background(), store); err != nil {
		t.Fatalf("ConfigureClientStore error: %v", err)
	}

	store.saveErr = fmt.Errorf("forced save error")
	err = provider.RegisterConfidentialClient(
		"rollback-client",
		"rollback-secret",
		"http://localhost:3000/rollback",
	)
	if err == nil {
		t.Fatalf("RegisterConfidentialClient must fail when client store save fails")
	}

	authErr := provider.AuthenticateTokenClient(TokenClientAuthentication{
		ClientID:     "rollback-client",
		AuthMethod:   TokenEndpointAuthMethodBasic,
		ClientSecret: "rollback-secret",
	})
	if authErr == nil {
		t.Fatalf("rolled-back client must not be registered")
	}
	assertOAuthError(t, authErr, "invalid_client")
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

type mockClientStore struct {
	loaded  []ClientSnapshot
	saved   [][]ClientSnapshot
	saveErr error
}

func (m *mockClientStore) LoadClients(_ context.Context) ([]ClientSnapshot, error) {
	copied := make([]ClientSnapshot, len(m.loaded))
	copy(copied, m.loaded)
	return copied, nil
}

func (m *mockClientStore) SaveClients(_ context.Context, clients []ClientSnapshot) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	snapshot := make([]ClientSnapshot, len(clients))
	for i, c := range clients {
		copyClient := c
		copyClient.RedirectURIs = append([]string(nil), c.RedirectURIs...)
		copyClient.JWTSigningPublicKeysPEM = append([]string(nil), c.JWTSigningPublicKeysPEM...)
		snapshot[i] = copyClient
	}
	m.saved = append(m.saved, snapshot)
	return nil
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

func parseJWTHeader(t *testing.T, rawToken string) map[string]any {
	t.Helper()

	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid jwt format")
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode jwt header error: %v", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(header, &claims); err != nil {
		t.Fatalf("unmarshal jwt header error: %v", err)
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

func jwksContainsKID(ks jwks, targetKID string) bool {
	for _, key := range ks.Keys {
		if key.Kid == targetKID {
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

func signClientAssertionWithoutJTI(t *testing.T, privateKeyPEM, clientID, audience string, expiresAt time.Time) string {
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

func assertPrivateJWTClientAuthentication(t *testing.T, provider *Provider, privateKeyPEM string) {
	t.Helper()

	assertion := signClientAssertion(
		t,
		privateKeyPEM,
		DefaultPrivateJWTClientID,
		testIssuer+"/oauth2/token",
		time.Now().UTC().Add(5*time.Minute),
	)
	if err := provider.AuthenticateTokenClient(TokenClientAuthentication{
		ClientID:            DefaultPrivateJWTClientID,
		AuthMethod:          TokenEndpointAuthMethodPrivate,
		ClientAssertionType: ClientAssertionTypeJWTBearer,
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
