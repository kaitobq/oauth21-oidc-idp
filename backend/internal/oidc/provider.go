package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// Provider exposes OIDC discovery metadata and JWKS.
type Provider struct {
	issuer string
	jwks   jwks
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
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

// NewProvider initializes an in-memory RSA key and metadata.
func NewProvider(issuer string) (*Provider, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if issuer == "" {
		return nil, fmt.Errorf("issuer must not be empty")
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

	return &Provider{
		issuer: issuer,
		jwks: jwks{Keys: []jwk{{
			Kty: "RSA",
			Use: "sig",
			Kid: kid,
			Alg: "RS256",
			N:   n,
			E:   e,
		}}},
	}, nil
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
			"client_secret_basic",
			"private_key_jwt",
		},
	}
}

func (p *Provider) JWKS() jwks {
	return p.jwks
}
