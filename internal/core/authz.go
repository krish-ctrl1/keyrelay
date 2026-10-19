package core

// Authorizer is an explicit (workload, route) allowlist. Anything not listed
// is denied; knowing a route's name grants nothing.
type Authorizer struct {
	allow map[string]map[WorkloadID]struct{}
}

// NewAuthorizer builds an allowlist from route definitions.
func NewAuthorizer(routes []*Route) *Authorizer {
	a := &Authorizer{allow: make(map[string]map[WorkloadID]struct{}, len(routes))}
	for _, r := range routes {
		set := make(map[WorkloadID]struct{}, len(r.Allow))
		for _, id := range r.Allow {
			set[id] = struct{}{}
		}
		a.allow[r.Name] = set
	}
	return a
}

// Allowed reports whether id may use route.
func (a *Authorizer) Allowed(id WorkloadID, route string) bool {
	if id == "" {
		return false
	}
	_, ok := a.allow[route][id]
	return ok
}
