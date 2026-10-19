package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// Engine is the single entry point used by front ends (HTTP proxy, future
// ext_proc). The two-step API makes the security ordering structural: a
// credential can only be requested with a *Grant, and a *Grant can only be
// obtained from Authorize.
type Engine struct {
	routes  map[string]*Route
	authz   *Authorizer
	secrets SecretProvider
}

// Grant is proof that a workload was authorized for a route.
type Grant struct {
	id    WorkloadID
	route *Route
}

// Workload returns the authorized identity.
func (g *Grant) Workload() WorkloadID { return g.id }

// Route returns the authorized route.
func (g *Grant) Route() *Route { return g.route }

// NewEngine validates routes and builds an engine.
func NewEngine(routes []*Route, secrets SecretProvider) (*Engine, error) {
	if secrets == nil {
		return nil, errors.New("secret provider is required")
	}
	m := make(map[string]*Route, len(routes))
	for _, r := range routes {
		if err := r.Validate(); err != nil {
			return nil, err
		}
		if _, dup := m[r.Name]; dup {
			return nil, fmt.Errorf("duplicate route %q", r.Name)
		}
		m[r.Name] = r
	}
	return &Engine{routes: m, authz: NewAuthorizer(routes), secrets: secrets}, nil
}

// Authorize decides whether id may use routeName. Unknown routes and
// non-allowlisted pairs produce the same 403 so route names cannot be probed.
// It never touches the cache or the secret store.
func (e *Engine) Authorize(id WorkloadID, routeName string) (*Grant, error) {
	if id == "" {
		return nil, Unauthenticated(ErrInvalidIdentity)
	}
	r, ok := e.routes[routeName]
	if !ok || !e.authz.Allowed(id, routeName) {
		return nil, Forbidden(nil)
	}
	return &Grant{id: id, route: r}, nil
}

// Credential fetches the route's credential and renders the header mutation.
func (e *Engine) Credential(ctx context.Context, g *Grant) (HeaderMutation, error) {
	if g == nil || g.route == nil {
		return HeaderMutation{}, Forbidden(nil)
	}
	s, err := e.secrets.GetSecret(ctx, g.route.Secret)
	if err != nil {
		return HeaderMutation{}, newError(http.StatusServiceUnavailable, ReasonCredentialUnavailable, err)
	}
	m, err := BuildMutation(g.route.Inject, s)
	if err != nil {
		return HeaderMutation{}, newError(http.StatusBadGateway, ReasonInjectionFailed, err)
	}
	return m, nil
}
