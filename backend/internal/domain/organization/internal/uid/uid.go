package uid

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// Generate returns a random 128-bit hex string.
func Generate() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate uid: %v", err))
	}
	return hex.EncodeToString(b)
}
