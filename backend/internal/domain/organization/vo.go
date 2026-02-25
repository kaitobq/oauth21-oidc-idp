package organization

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/kaitobq/oauth21-oidc-idp/backend/internal/domain/organization/internal/uid"
)

// ID is the unique identifier of an Organization.
type ID string

func NewID() ID {
	return ID(uid.Generate())
}

func ParseID(s string) (ID, error) {
	if s == "" {
		return "", errors.New("organization id must not be empty")
	}
	return ID(s), nil
}

func (id ID) String() string { return string(id) }

// Name is the URL-safe slug for an Organization.
type Name string

func NewName(s string) (Name, error) {
	trimmed := strings.TrimSpace(s)
	n := utf8.RuneCountInString(trimmed)
	if n < 1 || n > 63 {
		return "", fmt.Errorf("organization name must be 1-63 characters, got %d", n)
	}
	return Name(trimmed), nil
}

func (n Name) String() string { return string(n) }

// DisplayName is the human-readable name of an Organization.
type DisplayName string

func NewDisplayName(s string) (DisplayName, error) {
	trimmed := strings.TrimSpace(s)
	n := utf8.RuneCountInString(trimmed)
	if n < 1 || n > 255 {
		return "", fmt.Errorf("display name must be 1-255 characters, got %d", n)
	}
	return DisplayName(trimmed), nil
}

func (d DisplayName) String() string { return string(d) }
