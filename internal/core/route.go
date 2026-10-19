package core

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var (
	routeNameRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	headerNameRE = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
)

// ValidRouteName reports whether name is a syntactically valid route name.
func ValidRouteName(name string) bool { return routeNameRE.MatchString(name) }

// InjectRule describes how a credential is placed on the upstream request.
type InjectRule struct {
	Header string   // header that carries the credential, e.g. "Authorization"
	Prefix string   // prepended to the secret, e.g. "Bearer "
	Strip  []string // additional caller-supplied headers to remove
}

// Route binds a destination upstream to a credential and an allowlist.
type Route struct {
	Name     string
	Upstream *url.URL
	Secret   SecretRef
	Inject   InjectRule
	Allow    []WorkloadID
}

// Validate checks that the route is internally consistent.
func (r *Route) Validate() error {
	if !ValidRouteName(r.Name) {
		return fmt.Errorf("route %q: name must match %s", r.Name, routeNameRE)
	}
	if r.Upstream == nil || r.Upstream.Host == "" || (r.Upstream.Scheme != "https" && r.Upstream.Scheme != "http") {
		return fmt.Errorf("route %q: upstream must be an absolute http(s) URL", r.Name)
	}
	if r.Upstream.User != nil || r.Upstream.RawQuery != "" || r.Upstream.Fragment != "" {
		return fmt.Errorf("route %q: upstream must not contain userinfo, query or fragment", r.Name)
	}
	if r.Secret.Mount == "" || r.Secret.Path == "" || r.Secret.Key == "" {
		return fmt.Errorf("route %q: secret mount, path and key are required", r.Name)
	}
	if strings.Contains(r.Secret.Path, "..") {
		return fmt.Errorf("route %q: secret path must not contain '..'", r.Name)
	}
	if !headerNameRE.MatchString(r.Inject.Header) {
		return fmt.Errorf("route %q: invalid inject header %q", r.Name, r.Inject.Header)
	}
	for _, h := range r.Inject.Strip {
		if !headerNameRE.MatchString(h) {
			return fmt.Errorf("route %q: invalid strip header %q", r.Name, h)
		}
	}
	if len(r.Allow) == 0 {
		return errors.New("route " + r.Name + ": allow list must not be empty")
	}
	return nil
}
