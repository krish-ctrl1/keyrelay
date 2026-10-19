package core

import (
	"errors"
	"net/http"
	"strings"
)

// ErrInjection is returned when a credential cannot be safely rendered.
var ErrInjection = errors.New("credential injection")

// HeaderMutation is the transport-neutral result of credential injection:
// remove these headers (case-insensitively), then set Name to Value. The HTTP
// proxy applies it to an http.Header; an ext_proc server would translate it
// into a HeaderMutation protobuf.
type HeaderMutation struct {
	Remove []string
	Name   string
	Value  Secret // rendered header value, e.g. "Bearer <secret>"

	secret Secret // raw credential, kept for leak scrubbing
}

// BuildMutation renders the credential for rule. It rejects values that could
// split or smuggle headers.
func BuildMutation(rule InjectRule, s Secret) (HeaderMutation, error) {
	v := s.Reveal()
	if v == "" {
		return HeaderMutation{}, errors.Join(ErrInjection, errors.New("empty credential"))
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; c < 0x20 || c == 0x7f {
			return HeaderMutation{}, errors.Join(ErrInjection, errors.New("credential contains control characters"))
		}
	}
	remove := make([]string, 0, 1+len(rule.Strip))
	remove = append(remove, rule.Header)
	remove = append(remove, rule.Strip...)
	return HeaderMutation{
		Remove: remove,
		Name:   rule.Header,
		Value:  NewSecret(rule.Prefix + v),
		secret: s,
	}, nil
}

// ApplyTo strips every caller-supplied value of the managed headers and sets
// the real credential.
func (m HeaderMutation) ApplyTo(h http.Header) {
	for _, name := range m.Remove {
		for k := range h {
			if strings.EqualFold(k, name) {
				delete(h, k)
			}
		}
	}
	h.Set(m.Name, m.Value.Reveal())
}

// Exposes reports whether s contains the raw credential. It is used to scrub
// upstream response headers that echo the credential back.
func (m HeaderMutation) Exposes(s string) bool {
	raw := m.secret.Reveal()
	return raw != "" && strings.Contains(s, raw)
}
