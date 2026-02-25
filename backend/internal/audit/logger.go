package audit

import (
	"encoding/json"
	"log"
	"strings"
	"sync"
	"time"
)

// Logger writes JSON-line audit events to the process logger.
type Logger struct {
	logger   *log.Logger
	detector *FailureAnomalyDetector
}

type FailureAnomalyDetector struct {
	mu        sync.Mutex
	window    time.Duration
	threshold int
	failures  map[string][]time.Time
}

type FailureAnomaly struct {
	Fingerprint string
	Count       int
}

func NewFailureAnomalyDetector(window time.Duration, threshold int) *FailureAnomalyDetector {
	if window <= 0 {
		window = 5 * time.Minute
	}
	if threshold <= 1 {
		threshold = 5
	}
	return &FailureAnomalyDetector{
		window:    window,
		threshold: threshold,
		failures:  map[string][]time.Time{},
	}
}

func New() *Logger {
	return NewWithLoggerAndDetector(log.Default(), NewFailureAnomalyDetector(5*time.Minute, 5))
}

func NewWithLogger(logger *log.Logger) *Logger {
	return NewWithLoggerAndDetector(logger, NewFailureAnomalyDetector(5*time.Minute, 5))
}

func NewWithLoggerAndDetector(logger *log.Logger, detector *FailureAnomalyDetector) *Logger {
	if logger == nil {
		return New()
	}
	return &Logger{logger: logger, detector: detector}
}

func (l *Logger) Log(event string, fields map[string]any) {
	if l == nil || l.logger == nil {
		return
	}

	now := time.Now().UTC()
	payload := map[string]any{
		"kind":      "audit",
		"event":     event,
		"timestamp": now.Format(time.RFC3339Nano),
	}
	for k, v := range fields {
		payload[k] = v
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		l.logger.Printf(`{"kind":"audit","event":"%s","marshal_error":%q}`, event, err.Error())
		return
	}
	l.logger.Print(string(encoded))

	if l.detector == nil {
		return
	}
	anomaly := l.detector.Observe(event, fields, now)
	if anomaly == nil {
		return
	}

	alert := map[string]any{
		"kind":          "audit_alert",
		"event":         event,
		"timestamp":     now.Format(time.RFC3339Nano),
		"alert_type":    "repeated_failure",
		"fingerprint":   anomaly.Fingerprint,
		"failure_count": anomaly.Count,
	}
	if clientID := stringField(fields, "client_id"); clientID != "" {
		alert["client_id"] = clientID
	}
	if oauthError := stringField(fields, "oauth_error"); oauthError != "" {
		alert["oauth_error"] = oauthError
	}
	encodedAlert, err := json.Marshal(alert)
	if err != nil {
		l.logger.Printf(`{"kind":"audit_alert","event":"%s","marshal_error":%q}`, event, err.Error())
		return
	}
	l.logger.Print(string(encodedAlert))
}

func (d *FailureAnomalyDetector) Observe(event string, fields map[string]any, now time.Time) *FailureAnomaly {
	if d == nil {
		return nil
	}
	fingerprint := failureFingerprint(event, fields)
	if fingerprint == "" {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := now.Add(-d.window)
	entries := d.failures[fingerprint]
	pruned := entries[:0]
	for _, t := range entries {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	pruned = append(pruned, now)
	d.failures[fingerprint] = pruned
	count := len(pruned)
	if count < d.threshold {
		return nil
	}
	if count != d.threshold && count%d.threshold != 0 {
		return nil
	}
	return &FailureAnomaly{
		Fingerprint: fingerprint,
		Count:       count,
	}
}

func failureFingerprint(event string, fields map[string]any) string {
	result := stringField(fields, "result")
	if result != "error" && result != "reject" {
		return ""
	}
	parts := []string{
		strings.TrimSpace(event),
		result,
		stringField(fields, "oauth_error"),
		stringField(fields, "client_id"),
		stringField(fields, "grant_type"),
		stringField(fields, "reason"),
	}
	return strings.Join(parts, "|")
}

func stringField(fields map[string]any, key string) string {
	if fields == nil {
		return ""
	}
	v, ok := fields[key].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(v)
}
