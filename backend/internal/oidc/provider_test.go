package oidc

import "testing"

func TestProviderDiscoveryAndJWKS(t *testing.T) {
	t.Parallel()

	provider, err := NewProvider("http://localhost:8080")
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}

	d := provider.Discovery()
	if d.Issuer != "http://localhost:8080" {
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
	if !contains(d.CodeChallengeMethodsSupported, "S256") {
		t.Fatalf("code_challenge_methods_supported must include S256")
	}
	if !contains(d.ScopesSupported, "openid") {
		t.Fatalf("scopes_supported must include openid")
	}

	ks := provider.JWKS()
	if len(ks.Keys) == 0 {
		t.Fatalf("jwks keys must not be empty")
	}
	if ks.Keys[0].N == "" || ks.Keys[0].E == "" {
		t.Fatalf("jwk modulus/exponent must not be empty")
	}
}

func contains(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}
