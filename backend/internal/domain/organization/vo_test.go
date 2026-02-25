package organization

import "testing"

func TestNewName(t *testing.T) {
	t.Parallel()

	if _, err := NewName("  sample-org  "); err != nil {
		t.Fatalf("expected valid name, got error: %v", err)
	}

	if _, err := NewName("   "); err == nil {
		t.Fatalf("expected error for empty name")
	}
}

func TestNewDisplayName(t *testing.T) {
	t.Parallel()

	if _, err := NewDisplayName("  Example Org  "); err != nil {
		t.Fatalf("expected valid display name, got error: %v", err)
	}

	if _, err := NewDisplayName(""); err == nil {
		t.Fatalf("expected error for empty display name")
	}
}
