package oidc

import (
	"context"
	"path/filepath"
	"testing"

	coreoidc "github.com/kaitobq/oauth21-oidc-idp/backend/internal/oidc"
)

func TestFileClientStoreSaveAndLoadClients(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "oidc", "clients.json")
	store, err := NewFileClientStore(storePath)
	if err != nil {
		t.Fatalf("NewFileClientStore error: %v", err)
	}

	original := []coreoidc.ClientSnapshot{
		{
			ID:                      "persisted-basic-client",
			RedirectURIs:            []string{"http://localhost:3000/callback"},
			TokenEndpointAuthMethod: coreoidc.TokenEndpointAuthMethodBasic,
			ClientSecret:            "persisted-secret",
		},
	}

	if err := store.SaveClients(context.Background(), original); err != nil {
		t.Fatalf("SaveClients error: %v", err)
	}

	loaded, err := store.LoadClients(context.Background())
	if err != nil {
		t.Fatalf("LoadClients error: %v", err)
	}
	if len(loaded) != len(original) {
		t.Fatalf("loaded client count mismatch: got=%d want=%d", len(loaded), len(original))
	}
	if loaded[0].ID != original[0].ID {
		t.Fatalf("client id mismatch: got=%s want=%s", loaded[0].ID, original[0].ID)
	}
	if loaded[0].ClientSecret != original[0].ClientSecret {
		t.Fatalf("client secret mismatch: got=%s want=%s", loaded[0].ClientSecret, original[0].ClientSecret)
	}
}
