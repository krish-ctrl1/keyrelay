package core

import (
	"context"
	"fmt"
	"log/slog"
)

const redacted = "[REDACTED]"

// Secret holds downstream credential material. Every formatting, logging and
// serialization path renders it as "[REDACTED]"; the only way to obtain the
// value is an explicit call to Reveal at the point of injection.
type Secret struct{ value string }

// NewSecret wraps a credential value.
func NewSecret(v string) Secret { return Secret{value: v} }

// Reveal returns the raw credential. Call it only when writing the value
// onto an outbound request.
func (s Secret) Reveal() string { return s.value }

// IsZero reports whether the secret is empty.
func (s Secret) IsZero() bool { return s.value == "" }

func (Secret) String() string               { return redacted }
func (Secret) GoString() string             { return redacted }
func (Secret) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte(redacted)) }
func (Secret) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// SecretRef locates a credential in the secret store. It describes where the
// credential lives, never what it is, so it is safe to log.
type SecretRef struct {
	Mount string // KV v2 mount, e.g. "secret"
	Path  string // path under the mount, e.g. "keyrelay/weather"
	Key   string // field inside the KV document, e.g. "api_key"
}

func (r SecretRef) String() string { return r.Mount + "/" + r.Path + "#" + r.Key }

// SecretProvider retrieves downstream credentials.
type SecretProvider interface {
	GetSecret(ctx context.Context, ref SecretRef) (Secret, error)
}
