package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	DefaultDevClientID              = "local-dev-client"
	DefaultDevClientRedirect        = "http://localhost:3000/callback"
	DefaultConfidentialClientID     = "local-confidential-client"
	DefaultConfidentialClientSecret = "local-confidential-secret"
	DefaultConfidentialRedirect     = "http://localhost:3000/callback"
	defaultACRValue                 = "urn:example:loa:1"
	defaultAMRMethod                = "pwd"
	authCodeTTL                     = 5 * time.Minute
	accessTokenTTLSeconds           = int64(3600)
	refreshTokenTTL                 = 30 * 24 * time.Hour
)

// OAuthError maps internal validation failures to OAuth2-compatible responses.
type OAuthError struct {
	Code        string
	Description string
	Status      int
}

func (e *OAuthError) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

func (e *OAuthError) Response() map[string]string {
	resp := map[string]string{"error": e.Code}
	if e.Description != "" {
		resp["error_description"] = e.Description
	}
	return resp
}

// Provider exposes OIDC discovery metadata, JWKS and minimal auth code + PKCE flow.
type Provider struct {
	issuer     string
	privateKey *rsa.PrivateKey
	jwks       jwks

	mu        sync.Mutex
	clients   map[string]*client
	authCodes map[string]*authorizationCode
	tokens    map[string]*refreshTokenGrant
}

type client struct {
	ID                      string
	RedirectURIs            map[string]struct{}
	TokenEndpointAuthMethod string
	ClientSecret            string
}

type authorizationCode struct {
	Code            string
	ClientID        string
	RedirectURI     string
	Scope           string
	State           string
	Nonce           string
	SessionID       string
	ACR             string
	AMR             []string
	AuthenticatedAt time.Time
	CodeChallenge   string
	Subject         string
	ExpiresAt       time.Time
	Used            bool
}

type refreshTokenGrant struct {
	Token           string
	ClientID        string
	Subject         string
	Scope           string
	SessionID       string
	ACR             string
	AMR             []string
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
	Used            bool
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type discoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ACRValuesSupported                []string `json:"acr_values_supported,omitempty"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

// TokenResponse is returned by the token endpoint.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// NewProvider initializes a signing key and in-memory state.
func NewProvider(issuer, devClientID, devClientRedirect string) (*Provider, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if issuer == "" {
		return nil, fmt.Errorf("issuer must not be empty")
	}

	devClientID = strings.TrimSpace(devClientID)
	if devClientID == "" {
		devClientID = DefaultDevClientID
	}
	devClientRedirect = strings.TrimSpace(devClientRedirect)
	if devClientRedirect == "" {
		devClientRedirect = DefaultDevClientRedirect
	}
	if _, err := url.ParseRequestURI(devClientRedirect); err != nil {
		return nil, fmt.Errorf("invalid dev client redirect uri: %w", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}

	pub := key.PublicKey
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	hash := sha256.Sum256(pub.N.Bytes())
	kid := hex.EncodeToString(hash[:8])

	provider := &Provider{
		issuer:     issuer,
		privateKey: key,
		jwks: jwks{Keys: []jwk{{
			Kty: "RSA",
			Use: "sig",
			Kid: kid,
			Alg: "RS256",
			N:   n,
			E:   e,
		}}},
		clients: map[string]*client{
			devClientID: {
				ID:                      devClientID,
				TokenEndpointAuthMethod: "none",
				RedirectURIs: map[string]struct{}{
					devClientRedirect: {},
				},
			},
		},
		authCodes: map[string]*authorizationCode{},
		tokens:    map[string]*refreshTokenGrant{},
	}

	if err := provider.RegisterConfidentialClient(
		DefaultConfidentialClientID,
		DefaultConfidentialClientSecret,
		DefaultConfidentialRedirect,
	); err != nil {
		return nil, fmt.Errorf("register default confidential client: %w", err)
	}

	return provider, nil
}

func (p *Provider) Discovery() discoveryDocument {
	return discoveryDocument{
		Issuer:                p.issuer,
		AuthorizationEndpoint: p.issuer + "/oauth2/authorize",
		TokenEndpoint:         p.issuer + "/oauth2/token",
		JWKSURI:               p.issuer + "/oauth2/jwks",
		ResponseTypesSupported: []string{
			"code",
		},
		GrantTypesSupported: []string{
			"authorization_code",
			"refresh_token",
		},
		CodeChallengeMethodsSupported: []string{
			"S256",
		},
		ACRValuesSupported: []string{
			defaultACRValue,
		},
		SubjectTypesSupported: []string{
			"public",
		},
		IDTokenSigningAlgValuesSupported: []string{
			"RS256",
		},
		ScopesSupported: []string{
			"openid",
			"profile",
			"email",
			"offline_access",
		},
		TokenEndpointAuthMethodsSupported: []string{
			"none",
			"client_secret_basic",
		},
	}
}

func (p *Provider) JWKS() jwks {
	return p.jwks
}

func (p *Provider) RegisterConfidentialClient(clientID, clientSecret, redirectURI string) error {
	clientID = strings.TrimSpace(clientID)
	clientSecret = strings.TrimSpace(clientSecret)
	redirectURI = strings.TrimSpace(redirectURI)

	if clientID == "" {
		return fmt.Errorf("confidential client_id must not be empty")
	}
	if clientSecret == "" {
		return fmt.Errorf("confidential client_secret must not be empty")
	}
	if redirectURI == "" {
		return fmt.Errorf("confidential redirect_uri must not be empty")
	}
	if _, err := url.ParseRequestURI(redirectURI); err != nil {
		return fmt.Errorf("invalid confidential client redirect uri: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.clients[clientID] = &client{
		ID:                      clientID,
		TokenEndpointAuthMethod: "client_secret_basic",
		ClientSecret:            clientSecret,
		RedirectURIs: map[string]struct{}{
			redirectURI: {},
		},
	}
	return nil
}

func (p *Provider) AuthenticateTokenClient(clientID, clientSecret, authMethod string) error {
	clientID = strings.TrimSpace(clientID)
	authMethod = strings.TrimSpace(authMethod)
	if authMethod == "" {
		authMethod = "none"
	}
	if clientID == "" {
		return &OAuthError{Code: "invalid_request", Description: "client_id is required", Status: 400}
	}

	p.mu.Lock()
	c, ok := p.clients[clientID]
	p.mu.Unlock()
	if !ok {
		return &OAuthError{Code: "invalid_client", Description: "unknown client_id", Status: 401}
	}

	requiredMethod := c.TokenEndpointAuthMethod
	if requiredMethod == "" {
		requiredMethod = "none"
	}
	if requiredMethod != authMethod {
		return &OAuthError{Code: "invalid_client", Description: "client authentication method is invalid", Status: 401}
	}

	switch requiredMethod {
	case "none":
		return nil
	case "client_secret_basic":
		if clientSecret == "" {
			return &OAuthError{Code: "invalid_client", Description: "client_secret is required", Status: 401}
		}
		if subtle.ConstantTimeCompare([]byte(clientSecret), []byte(c.ClientSecret)) != 1 {
			return &OAuthError{Code: "invalid_client", Description: "client authentication failed", Status: 401}
		}
		return nil
	default:
		return &OAuthError{Code: "server_error", Description: "unsupported client authentication configuration", Status: 500}
	}
}

func (p *Provider) Authorize(responseType, clientID, redirectURI, scope, state, nonce, acrValues, codeChallenge, codeChallengeMethod string) (string, error) {
	responseType = strings.TrimSpace(responseType)
	clientID = strings.TrimSpace(clientID)
	redirectURI = strings.TrimSpace(redirectURI)
	codeChallenge = strings.TrimSpace(codeChallenge)
	codeChallengeMethod = strings.TrimSpace(codeChallengeMethod)
	scope = strings.TrimSpace(scope)
	nonce = strings.TrimSpace(nonce)
	acrValues = strings.TrimSpace(acrValues)

	if responseType != "code" {
		return "", &OAuthError{Code: "unsupported_response_type", Description: "response_type must be code", Status: 400}
	}
	if clientID == "" {
		return "", &OAuthError{Code: "invalid_request", Description: "client_id is required", Status: 400}
	}
	if redirectURI == "" {
		return "", &OAuthError{Code: "invalid_request", Description: "redirect_uri is required", Status: 400}
	}
	if codeChallenge == "" {
		return "", &OAuthError{Code: "invalid_request", Description: "code_challenge is required", Status: 400}
	}
	if codeChallengeMethod != "S256" {
		return "", &OAuthError{Code: "invalid_request", Description: "code_challenge_method must be S256", Status: 400}
	}
	acr, err := resolveACR(acrValues)
	if err != nil {
		return "", err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	c, ok := p.clients[clientID]
	if !ok {
		return "", &OAuthError{Code: "unauthorized_client", Description: "unknown client_id", Status: 400}
	}
	if _, ok := c.RedirectURIs[redirectURI]; !ok {
		return "", &OAuthError{Code: "invalid_request", Description: "redirect_uri is not allowed", Status: 400}
	}

	code, err := randomToken(32)
	if err != nil {
		return "", fmt.Errorf("generate authorization code: %w", err)
	}
	sessionID, err := randomToken(32)
	if err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}
	if scope == "" {
		scope = "openid"
	}

	authenticatedAt := time.Now().UTC()
	p.authCodes[code] = &authorizationCode{
		Code:            code,
		ClientID:        clientID,
		RedirectURI:     redirectURI,
		Scope:           scope,
		State:           state,
		Nonce:           nonce,
		SessionID:       sessionID,
		ACR:             acr,
		AMR:             []string{defaultAMRMethod},
		AuthenticatedAt: authenticatedAt,
		CodeChallenge:   codeChallenge,
		Subject:         "user-0001",
		ExpiresAt:       authenticatedAt.Add(authCodeTTL),
	}

	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", &OAuthError{Code: "invalid_request", Description: "redirect_uri is invalid", Status: 400}
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (p *Provider) ExchangeAuthorizationCode(grantType, code, redirectURI, clientID, codeVerifier string) (*TokenResponse, error) {
	grantType = strings.TrimSpace(grantType)
	code = strings.TrimSpace(code)
	redirectURI = strings.TrimSpace(redirectURI)
	clientID = strings.TrimSpace(clientID)
	codeVerifier = strings.TrimSpace(codeVerifier)

	if grantType != "authorization_code" {
		return nil, &OAuthError{Code: "unsupported_grant_type", Description: "grant_type must be authorization_code", Status: 400}
	}
	if code == "" || redirectURI == "" || clientID == "" || codeVerifier == "" {
		return nil, &OAuthError{Code: "invalid_request", Description: "code, redirect_uri, client_id and code_verifier are required", Status: 400}
	}

	p.mu.Lock()
	entry, ok := p.authCodes[code]
	if !ok {
		p.mu.Unlock()
		return nil, &OAuthError{Code: "invalid_grant", Description: "authorization code is invalid", Status: 400}
	}
	if entry.Used {
		p.mu.Unlock()
		return nil, &OAuthError{Code: "invalid_grant", Description: "authorization code was already used", Status: 400}
	}
	if time.Now().UTC().After(entry.ExpiresAt) {
		delete(p.authCodes, code)
		p.mu.Unlock()
		return nil, &OAuthError{Code: "invalid_grant", Description: "authorization code has expired", Status: 400}
	}
	if entry.ClientID != clientID {
		p.mu.Unlock()
		return nil, &OAuthError{Code: "invalid_grant", Description: "client_id mismatch", Status: 400}
	}
	if entry.RedirectURI != redirectURI {
		p.mu.Unlock()
		return nil, &OAuthError{Code: "invalid_grant", Description: "redirect_uri mismatch", Status: 400}
	}

	sum := sha256.Sum256([]byte(codeVerifier))
	expectedChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(expectedChallenge), []byte(entry.CodeChallenge)) != 1 {
		p.mu.Unlock()
		return nil, &OAuthError{Code: "invalid_grant", Description: "code_verifier mismatch", Status: 400}
	}

	entry.Used = true
	subject := entry.Subject
	scope := entry.Scope
	nonce := entry.Nonce
	sessionID := entry.SessionID
	acr := entry.ACR
	amr := append([]string(nil), entry.AMR...)
	authenticatedAt := entry.AuthenticatedAt
	p.mu.Unlock()

	accessToken, err := randomToken(32)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	resp := &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   accessTokenTTLSeconds,
		Scope:       scope,
	}

	if hasScope(scope, "offline_access") {
		refreshToken, err := randomToken(32)
		if err != nil {
			return nil, fmt.Errorf("generate refresh token: %w", err)
		}
		p.mu.Lock()
		p.tokens[refreshToken] = &refreshTokenGrant{
			Token:           refreshToken,
			ClientID:        clientID,
			Subject:         subject,
			Scope:           scope,
			SessionID:       sessionID,
			ACR:             acr,
			AMR:             append([]string(nil), amr...),
			AuthenticatedAt: authenticatedAt,
			ExpiresAt:       time.Now().UTC().Add(refreshTokenTTL),
		}
		p.mu.Unlock()
		resp.RefreshToken = refreshToken
	}

	if hasScope(scope, "openid") {
		idToken, err := p.signIDToken(subject, clientID, nonce, acr, amr, authenticatedAt, sessionID, accessToken)
		if err != nil {
			return nil, fmt.Errorf("sign id token: %w", err)
		}
		resp.IDToken = idToken
	}

	return resp, nil
}

func (p *Provider) ExchangeRefreshToken(grantType, refreshToken, clientID, scope string) (*TokenResponse, error) {
	grantType = strings.TrimSpace(grantType)
	refreshToken = strings.TrimSpace(refreshToken)
	clientID = strings.TrimSpace(clientID)
	scope = strings.TrimSpace(scope)

	if grantType != "refresh_token" {
		return nil, &OAuthError{Code: "unsupported_grant_type", Description: "grant_type must be refresh_token", Status: 400}
	}
	if refreshToken == "" || clientID == "" {
		return nil, &OAuthError{Code: "invalid_request", Description: "refresh_token and client_id are required", Status: 400}
	}

	p.mu.Lock()
	entry, ok := p.tokens[refreshToken]
	if !ok {
		p.mu.Unlock()
		return nil, &OAuthError{Code: "invalid_grant", Description: "refresh token is invalid", Status: 400}
	}
	if entry.Used {
		p.mu.Unlock()
		return nil, &OAuthError{Code: "invalid_grant", Description: "refresh token was already used", Status: 400}
	}
	if time.Now().UTC().After(entry.ExpiresAt) {
		delete(p.tokens, refreshToken)
		p.mu.Unlock()
		return nil, &OAuthError{Code: "invalid_grant", Description: "refresh token has expired", Status: 400}
	}
	if entry.ClientID != clientID {
		p.mu.Unlock()
		return nil, &OAuthError{Code: "invalid_grant", Description: "client_id mismatch", Status: 400}
	}

	issuedScope := entry.Scope
	if scope != "" {
		if !isScopeSubset(scope, entry.Scope) {
			p.mu.Unlock()
			return nil, &OAuthError{Code: "invalid_scope", Description: "requested scope exceeds originally granted scope", Status: 400}
		}
		issuedScope = scope
	}

	entry.Used = true
	subject := entry.Subject
	sessionID := entry.SessionID
	acr := entry.ACR
	amr := append([]string(nil), entry.AMR...)
	authenticatedAt := entry.AuthenticatedAt
	p.mu.Unlock()

	accessToken, err := randomToken(32)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}
	nextRefreshToken, err := randomToken(32)
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	p.mu.Lock()
	p.tokens[nextRefreshToken] = &refreshTokenGrant{
		Token:           nextRefreshToken,
		ClientID:        clientID,
		Subject:         subject,
		Scope:           issuedScope,
		SessionID:       sessionID,
		ACR:             acr,
		AMR:             append([]string(nil), amr...),
		AuthenticatedAt: authenticatedAt,
		ExpiresAt:       time.Now().UTC().Add(refreshTokenTTL),
	}
	p.mu.Unlock()

	resp := &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    accessTokenTTLSeconds,
		Scope:        issuedScope,
		RefreshToken: nextRefreshToken,
	}

	if hasScope(issuedScope, "openid") {
		idToken, err := p.signIDToken(subject, clientID, "", acr, amr, authenticatedAt, sessionID, accessToken)
		if err != nil {
			return nil, fmt.Errorf("sign id token: %w", err)
		}
		resp.IDToken = idToken
	}

	return resp, nil
}

func (p *Provider) signIDToken(subject, audience, nonce, acr string, amr []string, authenticatedAt time.Time, sessionID, accessToken string) (string, error) {
	now := time.Now().UTC()
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": p.jwks.Keys[0].Kid,
	}
	claims := map[string]any{
		"iss": p.issuer,
		"sub": subject,
		"aud": audience,
		"azp": audience,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
	if !authenticatedAt.IsZero() {
		claims["auth_time"] = authenticatedAt.Unix()
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if acr != "" {
		claims["acr"] = acr
	}
	if len(amr) > 0 {
		claims["amr"] = append([]string(nil), amr...)
	}
	if sessionID != "" {
		claims["sid"] = sessionID
	}
	if accessToken != "" {
		claims["at_hash"] = accessTokenHash(accessToken)
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal jwt header: %w", err)
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal jwt claims: %w", err)
	}

	headerEnc := base64.RawURLEncoding.EncodeToString(headerBytes)
	claimsEnc := base64.RawURLEncoding.EncodeToString(claimsBytes)
	signingInput := headerEnc + "." + claimsEnc

	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// accessTokenHash computes OIDC at_hash for RS256: left-most half of SHA-256(access_token), base64url.
func accessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

func randomToken(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hasScope(scope, target string) bool {
	for _, s := range strings.Fields(scope) {
		if s == target {
			return true
		}
	}
	return false
}

func isScopeSubset(requestedScope, originalScope string) bool {
	original := map[string]struct{}{}
	for _, s := range strings.Fields(originalScope) {
		original[s] = struct{}{}
	}
	for _, s := range strings.Fields(requestedScope) {
		if _, ok := original[s]; !ok {
			return false
		}
	}
	return true
}

func resolveACR(acrValues string) (string, error) {
	if acrValues == "" {
		return defaultACRValue, nil
	}
	for _, acr := range strings.Fields(acrValues) {
		if acr == defaultACRValue {
			return acr, nil
		}
	}
	return "", &OAuthError{Code: "invalid_request", Description: "acr_values includes unsupported value", Status: 400}
}
