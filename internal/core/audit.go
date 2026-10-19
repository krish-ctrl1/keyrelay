package core

import (
	"context"
	"io"
	"log/slog"
	"time"
)

// Event is one audit record. Its fields are fixed by construction; there is
// no field that could carry a credential, header value, token or SecretID.
type Event struct {
	RequestID  string
	WorkloadID string
	Route      string
	Method     string
	Path       string // URL path only; the query string is never logged
	Remote     string
	Decision   string // "allow" or "deny"
	Reason     string
	Status     int
	Duration   time.Duration
}

// Auditor writes structured JSON audit events.
type Auditor struct{ log *slog.Logger }

// NewAuditor writes JSON lines to w.
func NewAuditor(w io.Writer) *Auditor {
	return &Auditor{log: slog.New(slog.NewJSONHandler(w, nil))}
}

// Record emits e.
func (a *Auditor) Record(e Event) {
	a.log.LogAttrs(context.Background(), slog.LevelInfo, "keyrelay.request",
		slog.String("request_id", e.RequestID),
		slog.String("workload_id", e.WorkloadID),
		slog.String("route", e.Route),
		slog.String("method", e.Method),
		slog.String("path", e.Path),
		slog.String("remote", e.Remote),
		slog.String("decision", e.Decision),
		slog.String("reason", e.Reason),
		slog.Int("status", e.Status),
		slog.Float64("duration_ms", float64(e.Duration.Microseconds())/1000),
	)
}
