package audit

import (
	"encoding/json"
	"log"
	"time"
)

// Logger writes JSON-line audit events to the process logger.
type Logger struct {
	logger *log.Logger
}

func New() *Logger {
	return &Logger{logger: log.Default()}
}

func NewWithLogger(logger *log.Logger) *Logger {
	if logger == nil {
		return New()
	}
	return &Logger{logger: logger}
}

func (l *Logger) Log(event string, fields map[string]any) {
	if l == nil || l.logger == nil {
		return
	}

	payload := map[string]any{
		"kind":      "audit",
		"event":     event,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
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
}
