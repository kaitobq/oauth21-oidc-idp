package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	coreoidc "github.com/kaitobq/oauth21-oidc-idp/backend/internal/oidc"
)

type filePayload struct {
	Version int                       `json:"version"`
	Clients []coreoidc.ClientSnapshot `json:"clients"`
}

type FileClientStore struct {
	path string
}

var _ coreoidc.ClientStore = (*FileClientStore)(nil)

func NewFileClientStore(path string) (*FileClientStore, error) {
	normalizedPath := strings.TrimSpace(path)
	if normalizedPath == "" {
		return nil, fmt.Errorf("client registry path must not be empty")
	}
	return &FileClientStore{path: filepath.Clean(normalizedPath)}, nil
}

func (s *FileClientStore) LoadClients(_ context.Context) ([]coreoidc.ClientSnapshot, error) {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read client registry file: %w", err)
	}
	if len(raw) == 0 {
		return nil, nil
	}

	var payload filePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("decode client registry file: %w", err)
	}
	return payload.Clients, nil
}

func (s *FileClientStore) SaveClients(_ context.Context, clients []coreoidc.ClientSnapshot) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("create client registry directory: %w", err)
	}

	payload := filePayload{
		Version: 1,
		Clients: clients,
	}
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("encode client registry payload: %w", err)
	}
	encoded = append(encoded, '\n')

	tempPath := s.path + ".tmp"
	if err := os.WriteFile(tempPath, encoded, 0o600); err != nil {
		return fmt.Errorf("write temporary client registry file: %w", err)
	}
	if err := os.Rename(tempPath, s.path); err != nil {
		return fmt.Errorf("replace client registry file: %w", err)
	}
	return nil
}
