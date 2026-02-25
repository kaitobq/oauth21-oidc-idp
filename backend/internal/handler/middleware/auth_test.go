package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAdminAuthStatic(t *testing.T) {
	t.Parallel()

	protected := AdminAuth(AdminAuthConfig{
		Mode:        AdminAuthModeStatic,
		StaticToken: "test-admin-token",
		Methods:     []string{http.MethodPost},
	}, ScopeRotateSigningKey)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	t.Run("method bypass", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin", nil)
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("unexpected status: got=%d want=%d", rec.Code, http.StatusNoContent)
		}
	})

	t.Run("missing bearer", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/admin", nil)
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("unexpected status: got=%d want=%d", rec.Code, http.StatusUnauthorized)
		}
	})

	t.Run("invalid bearer", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/admin", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("unexpected status: got=%d want=%d", rec.Code, http.StatusUnauthorized)
		}
	})

	t.Run("valid bearer", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/admin", nil)
		req.Header.Set("Authorization", "Bearer test-admin-token")
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("unexpected status: got=%d want=%d", rec.Code, http.StatusNoContent)
		}
	})
}

func TestAdminAuthStaticMissingTokenConfig(t *testing.T) {
	t.Parallel()

	protected := AdminAuth(AdminAuthConfig{
		Mode:        AdminAuthModeStatic,
		StaticToken: "   ",
		Methods:     []string{http.MethodPost},
	}, ScopeRotateSigningKey)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/admin", nil)
	req.Header.Set("Authorization", "Bearer any-token")
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("unexpected status: got=%d want=%d", rec.Code, http.StatusInternalServerError)
	}
}

func TestAdminAuthJWT(t *testing.T) {
	t.Parallel()

	secret := "admin-secret"
	issuer := "oidc-admin-tests"
	audience := "oidc-admin-api"

	protected := AdminAuth(AdminAuthConfig{
		Mode:        AdminAuthModeJWT,
		JWTSecret:   secret,
		JWTIssuer:   issuer,
		JWTAudience: audience,
		Methods:     []string{http.MethodPost},
	}, ScopeRotateSigningKey)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	t.Run("valid jwt", func(t *testing.T) {
		token := signHS256JWT(t, secret, map[string]any{
			"iss":   issuer,
			"aud":   audience,
			"exp":   time.Now().UTC().Add(5 * time.Minute).Unix(),
			"scope": ScopeRotateSigningKey + " " + ScopeRotatePrivateJWTClientKey,
		})
		req := httptest.NewRequest(http.MethodPost, "/admin", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("unexpected status: got=%d want=%d", rec.Code, http.StatusNoContent)
		}
	})

	t.Run("insufficient scope", func(t *testing.T) {
		token := signHS256JWT(t, secret, map[string]any{
			"iss":   issuer,
			"aud":   audience,
			"exp":   time.Now().UTC().Add(5 * time.Minute).Unix(),
			"scope": ScopeRotatePrivateJWTClientKey,
		})
		req := httptest.NewRequest(http.MethodPost, "/admin", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("unexpected status: got=%d want=%d", rec.Code, http.StatusForbidden)
		}
		if header := rec.Header().Get("WWW-Authenticate"); !strings.Contains(header, `error="insufficient_scope"`) {
			t.Fatalf("WWW-Authenticate must include insufficient_scope, got %q", header)
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		token := signHS256JWT(t, "wrong-secret", map[string]any{
			"iss":   issuer,
			"aud":   audience,
			"exp":   time.Now().UTC().Add(5 * time.Minute).Unix(),
			"scope": ScopeRotateSigningKey,
		})
		req := httptest.NewRequest(http.MethodPost, "/admin", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("unexpected status: got=%d want=%d", rec.Code, http.StatusUnauthorized)
		}
	})
}

func TestAdminAuthJWTMissingSecret(t *testing.T) {
	t.Parallel()

	protected := AdminAuth(AdminAuthConfig{
		Mode:      AdminAuthModeJWT,
		JWTSecret: "   ",
		Methods:   []string{http.MethodPost},
	}, ScopeRotateSigningKey)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	token := signHS256JWT(t, "any-secret", map[string]any{
		"exp":   time.Now().UTC().Add(5 * time.Minute).Unix(),
		"scope": ScopeRotateSigningKey,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("unexpected status: got=%d want=%d", rec.Code, http.StatusInternalServerError)
	}
}

func signHS256JWT(t *testing.T, secret string, claims map[string]any) string {
	t.Helper()

	headerBytes, err := json.Marshal(map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	})
	if err != nil {
		t.Fatalf("marshal header error: %v", err)
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims error: %v", err)
	}

	headerEnc := base64.RawURLEncoding.EncodeToString(headerBytes)
	claimsEnc := base64.RawURLEncoding.EncodeToString(claimsBytes)
	signingInput := headerEnc + "." + claimsEnc

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signingInput))
	signature := mac.Sum(nil)
	signatureEnc := base64.RawURLEncoding.EncodeToString(signature)
	return signingInput + "." + signatureEnc
}
