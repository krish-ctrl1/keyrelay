// Package proxy is KeyRelay's HTTP front end: an mTLS listener plus an
// httputil.ReverseProxy that delegates every decision to internal/core.
package proxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"github.com/keyrelay/keyrelay/internal/core"
)

// RoutePrefix is the path prefix under which routes are exposed:
// https://keyrelay:8443/r/<route>/<upstream path>.
const RoutePrefix = "/r/"

// Response headers set by KeyRelay itself.
const (
	HeaderRequestID = "X-KeyRelay-Request-ID"
	HeaderError     = "X-KeyRelay-Error"
)

// Options configures a Server.
type Options struct {
	Engine    *core.Engine
	Auditor   *core.Auditor
	Transport http.RoundTripper // upstream transport; nil uses UpstreamTransport(nil)
}

// Server is an http.Handler that authenticates, authorizes, injects and
// proxies.
type Server struct {
	engine *core.Engine
	audit  *core.Auditor
	rp     *httputil.ReverseProxy
}

type stateKey struct{}

type reqState struct {
	grant    *core.Grant
	rest     string
	query    string
	mutation core.HeaderMutation
	reason   string
}

// New builds a Server.
func New(opts Options) (*Server, error) {
	if opts.Engine == nil || opts.Auditor == nil {
		return nil, errors.New("proxy: engine and auditor are required")
	}
	if opts.Transport == nil {
		opts.Transport = UpstreamTransport(nil)
	}
	s := &Server{engine: opts.Engine, audit: opts.Auditor}
	s.rp = &httputil.ReverseProxy{
		Rewrite:        s.rewrite,
		Transport:      opts.Transport,
		ModifyResponse: s.modifyResponse,
		ErrorHandler:   s.upstreamError,
		ErrorLog:       nopLogger(),
	}
	return s, nil
}

// ServeHTTP implements http.Handler. Ordering is security-critical:
// identity -> route parse -> authorization -> credential -> proxy.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w}
	ev := core.Event{
		RequestID: newRequestID(),
		Method:    r.Method,
		Path:      r.URL.Path,
		Remote:    r.RemoteAddr,
		Decision:  "deny",
	}
	rec.Header().Set(HeaderRequestID, ev.RequestID)
	defer func() {
		ev.Status = rec.statusCode()
		ev.Duration = time.Since(start)
		s.audit.Record(ev)
	}()
	fail := func(err error) {
		e := core.AsError(err)
		ev.Reason = e.Reason
		writeError(rec, e.Status, e.Reason, ev.RequestID)
	}

	id, err := identityFromRequest(r)
	if err != nil {
		fail(core.Unauthenticated(err))
		return
	}
	ev.WorkloadID = string(id)

	routeName, rest, err := splitRoutePath(r)
	if err != nil {
		fail(err)
		return
	}
	ev.Route = routeName

	grant, err := s.engine.Authorize(id, routeName)
	if err != nil {
		fail(err)
		return
	}
	mutation, err := s.engine.Credential(r.Context(), grant)
	if err != nil {
		fail(err)
		return
	}

	ev.Decision = "allow"
	st := &reqState{grant: grant, rest: rest, query: r.URL.RawQuery, mutation: mutation}
	s.rp.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), stateKey{}, st)))
	ev.Reason = st.reason
}

// identityFromRequest derives identity only from the verified peer
// certificate. Headers are never consulted.
func identityFromRequest(r *http.Request) (core.WorkloadID, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		return "", errors.New("no verified client certificate")
	}
	return core.IdentityFromCertificate(r.TLS.PeerCertificates[0])
}

// splitRoutePath extracts the route name and the remaining upstream path,
// rejecting anything that could escape the route's upstream base path.
func splitRoutePath(r *http.Request) (string, string, error) {
	esc := r.URL.EscapedPath()
	if !strings.HasPrefix(esc, RoutePrefix) {
		return "", "", core.Forbidden(nil)
	}
	lower := strings.ToLower(esc)
	for _, bad := range []string{"%2f", "%2e", "%5c", "\\"} {
		if strings.Contains(lower, bad) {
			return "", "", core.BadRequest(errors.New("encoded path separators are not allowed"))
		}
	}
	for _, seg := range strings.Split(r.URL.Path, "/") {
		if seg == "." || seg == ".." {
			return "", "", core.BadRequest(errors.New("dot segments are not allowed"))
		}
	}
	name, tail, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, RoutePrefix), "/")
	if !core.ValidRouteName(name) {
		return "", "", core.Forbidden(nil)
	}
	return name, "/" + tail, nil
}

func (s *Server) rewrite(pr *httputil.ProxyRequest) {
	st := pr.In.Context().Value(stateKey{}).(*reqState)
	up := st.grant.Route().Upstream

	pr.Out.URL.Path = st.rest
	pr.Out.URL.RawPath = ""
	pr.Out.URL.RawQuery = st.query
	pr.SetURL(up) // scheme, host and base path come only from config
	pr.Out.Host = up.Host
	// Rewrite mode already drops hop-by-hop and X-Forwarded-* headers from the
	// inbound request; we intentionally do not add new forwarding headers.
	st.mutation.ApplyTo(pr.Out.Header)
}

func (s *Server) modifyResponse(resp *http.Response) error {
	st, _ := resp.Request.Context().Value(stateKey{}).(*reqState)
	if st == nil {
		return nil
	}
	// Defence in depth: drop any upstream response header that echoes the
	// credential back toward the agent.
	for k, vals := range resp.Header {
		for _, v := range vals {
			if st.mutation.Exposes(v) {
				resp.Header.Del(k)
				break
			}
		}
	}
	return nil
}

func (s *Server) upstreamError(w http.ResponseWriter, r *http.Request, _ error) {
	if st, ok := r.Context().Value(stateKey{}).(*reqState); ok {
		st.reason = core.ReasonUpstreamError
	}
	writeError(w, http.StatusBadGateway, core.ReasonUpstreamError, w.Header().Get(HeaderRequestID))
}

func writeError(w http.ResponseWriter, status int, reason, requestID string) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set(HeaderError, reason)
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": reason, "request_id": requestID})
}

// ServerTLSConfig builds the listener TLS config: client certificates are
// mandatory and must chain to clientCAFile.
func ServerTLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}
	pool, err := loadPool(clientCAFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// LoadUpstreamTransport returns UpstreamTransport using caFile (if set) as
// the trusted roots for upstream TLS.
func LoadUpstreamTransport(caFile string) (http.RoundTripper, error) {
	if caFile == "" {
		return UpstreamTransport(nil), nil
	}
	pool, err := loadPool(caFile)
	if err != nil {
		return nil, err
	}
	return UpstreamTransport(pool), nil
}

// UpstreamTransport returns the transport used for upstream calls. It never
// uses environment proxies, so a credential cannot be routed through an
// unexpected intermediary.
func UpstreamTransport(roots *x509.CertPool) *http.Transport {
	return &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
}

func loadPool(file string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates in %s", file)
	}
	return pool, nil
}

func newRequestID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
