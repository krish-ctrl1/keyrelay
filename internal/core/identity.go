package core

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// WorkloadID is the canonical identity of an agent or workload, derived from
// the single URI SAN of its verified X.509 client certificate
// (for example "spiffe://demo.keyrelay/agent/weather-bot").
type WorkloadID string

// ErrInvalidIdentity is returned when a certificate or configured identity
// cannot be turned into a canonical WorkloadID.
var ErrInvalidIdentity = errors.New("invalid workload identity")

// IdentityFromCertificate derives the canonical WorkloadID from a client
// certificate. The certificate must already have been verified against the
// trusted client CA by the TLS layer. Exactly one URI SAN is required; DNS,
// IP, email SANs and the Subject CN are ignored.
func IdentityFromCertificate(cert *x509.Certificate) (WorkloadID, error) {
	if cert == nil {
		return "", fmt.Errorf("%w: no certificate", ErrInvalidIdentity)
	}
	if n := len(cert.URIs); n != 1 {
		return "", fmt.Errorf("%w: certificate must contain exactly one URI SAN, found %d", ErrInvalidIdentity, n)
	}
	return canonicalize(cert.URIs[0])
}

// ParseWorkloadID canonicalizes an identity string from configuration so it
// can be compared with identities derived from certificates.
func ParseWorkloadID(raw string) (WorkloadID, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("%w: %q is not a URI", ErrInvalidIdentity, raw)
	}
	return canonicalize(u)
}

func canonicalize(u *url.URL) (WorkloadID, error) {
	switch {
	case u == nil:
		return "", fmt.Errorf("%w: empty URI", ErrInvalidIdentity)
	case u.Scheme == "" || u.Opaque != "":
		return "", fmt.Errorf("%w: URI must be absolute and hierarchical", ErrInvalidIdentity)
	case u.Host == "":
		return "", fmt.Errorf("%w: URI must have a trust domain/host", ErrInvalidIdentity)
	case u.User != nil:
		return "", fmt.Errorf("%w: URI must not contain userinfo", ErrInvalidIdentity)
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "":
		return "", fmt.Errorf("%w: URI must not contain a query or fragment", ErrInvalidIdentity)
	}
	path := u.EscapedPath()
	for _, seg := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if seg == "." || seg == ".." {
			return "", fmt.Errorf("%w: URI path must not contain dot segments", ErrInvalidIdentity)
		}
	}
	path = strings.TrimSuffix(path, "/")
	return WorkloadID(strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + path), nil
}
