package audit

import (
	"bytes"
	"encoding/json"
	"log"
	"strings"
	"testing"
)

func TestLoggerLogJSONLine(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	logger := NewWithLogger(log.New(&buffer, "", 0))
	logger.Log("oidc.token", map[string]any{
		"result":    "success",
		"client_id": "test-client",
	})

	line := strings.TrimSpace(buffer.String())
	if line == "" {
		t.Fatalf("audit log line must not be empty")
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		t.Fatalf("audit log must be valid json: %v", err)
	}
	if payload["kind"] != "audit" {
		t.Fatalf("kind mismatch: got=%v want=audit", payload["kind"])
	}
	if payload["event"] != "oidc.token" {
		t.Fatalf("event mismatch: got=%v want=oidc.token", payload["event"])
	}
	if payload["result"] != "success" {
		t.Fatalf("result mismatch: got=%v want=success", payload["result"])
	}
	if payload["client_id"] != "test-client" {
		t.Fatalf("client_id mismatch: got=%v want=test-client", payload["client_id"])
	}
	if _, ok := payload["timestamp"]; !ok {
		t.Fatalf("timestamp must exist")
	}
}
