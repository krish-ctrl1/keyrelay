// Package core contains KeyRelay's transport-neutral decision and credential
// logic: workload identity, authorization, secret retrieval and caching,
// credential injection, and audit. It deliberately knows nothing about
// listeners or reverse proxies so it can be wrapped by the v0.01 HTTP proxy or
// by a future Envoy ext_proc server without modification.
package core

import (
	"errors"
	"net/http"
)

// Stable, client-safe reason codes. These are returned to callers and written
// to audit logs, so they must never embed secret material.
const (
	ReasonUnauthenticated       = "unauthenticated"
	ReasonForbidden             = "forbidden"
	ReasonBadRequest            = "bad_request"
	ReasonCredentialUnavailable = "credential_unavailable"
	ReasonInjectionFailed       = "credential_injection_failed"
	ReasonUpstreamError         = "upstream_error"
)

// Error is a fail-closed decision carrying the HTTP status and a stable reason.
// The wrapped cause is for internal diagnostics only and is constructed so
// that it never contains credentials, tokens or SecretIDs.
type Error struct {
	Status int
	Reason string
	cause  error
}

func (e *Error) Error() string {
	if e.cause != nil {
		return e.Reason + ": " + e.cause.Error()
	}
	return e.Reason
}

func (e *Error) Unwrap() error { return e.cause }

func newError(status int, reason string, cause error) *Error {
	return &Error{Status: status, Reason: reason, cause: cause}
}

// Unauthenticated builds a 401 decision.
func Unauthenticated(cause error) *Error {
	return newError(http.StatusUnauthorized, ReasonUnauthenticated, cause)
}

// Forbidden builds a 403 decision.
func Forbidden(cause error) *Error {
	return newError(http.StatusForbidden, ReasonForbidden, cause)
}

// BadRequest builds a 400 decision.
func BadRequest(cause error) *Error {
	return newError(http.StatusBadRequest, ReasonBadRequest, cause)
}

// AsError converts any error into a *Error, defaulting to 503 so that
// unexpected failures fail closed.
func AsError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return newError(http.StatusServiceUnavailable, ReasonCredentialUnavailable, err)
}
