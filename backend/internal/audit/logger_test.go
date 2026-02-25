package audit

import (
	"bytes"
	"encoding/json"
	"log"
	"strings"
	"testing"
	"time"
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

func TestLoggerEmitsAnomalyAlertOnRepeatedFailures(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	detector := NewFailureAnomalyDetector(5*time.Minute, 2)
	logger := NewWithLoggerAndDetector(log.New(&buffer, "", 0), detector)

	logger.Log("oidc.token", map[string]any{
		"result":      "error",
		"oauth_error": "invalid_client",
		"client_id":   "test-client",
		"grant_type":  "authorization_code",
	})
	logger.Log("oidc.token", map[string]any{
		"result":      "error",
		"oauth_error": "invalid_client",
		"client_id":   "test-client",
		"grant_type":  "authorization_code",
	})

	lines := strings.Split(strings.TrimSpace(buffer.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 log lines (2 audit + 1 alert), got %d", len(lines))
	}

	var alert map[string]any
	if err := json.Unmarshal([]byte(lines[2]), &alert); err != nil {
		t.Fatalf("alert line must be valid json: %v", err)
	}
	if alert["kind"] != "audit_alert" {
		t.Fatalf("alert kind mismatch: got=%v want=audit_alert", alert["kind"])
	}
	if alert["alert_type"] != "repeated_failure" {
		t.Fatalf("alert type mismatch: got=%v want=repeated_failure", alert["alert_type"])
	}
	if alert["event"] != "oidc.token" {
		t.Fatalf("alert event mismatch: got=%v want=oidc.token", alert["event"])
	}
}
