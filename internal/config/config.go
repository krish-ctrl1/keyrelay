// Package config loads and validates KeyRelay's YAML configuration and
// converts it into core types.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/keyrelay/keyrelay/internal/core"
)

// Config is the on-disk configuration.
type Config struct {
	Listen      string      `yaml:"listen"`
	TLS         TLSConfig   `yaml:"tls"`
	Vault       VaultConfig `yaml:"vault"`
	Cache       CacheConfig `yaml:"cache"`
	UpstreamTLS UpstreamTLS `yaml:"upstream_tls"`
	Routes      []Route     `yaml:"routes"`
}

type TLSConfig struct {
	CertFile     string `yaml:"cert_file"`
	KeyFile      string `yaml:"key_file"`
	ClientCAFile string `yaml:"client_ca_file"`
}

type VaultConfig struct {
	Address   string        `yaml:"address"`
	Namespace string        `yaml:"namespace"`
	Timeout   time.Duration `yaml:"timeout"`
	CAFile    string        `yaml:"ca_file"`
	AppRole   AppRole       `yaml:"approle"`
}

type AppRole struct {
	Mount        string `yaml:"mount"`
	RoleIDFile   string `yaml:"role_id_file"`
	SecretIDFile string `yaml:"secret_id_file"`
}

type CacheConfig struct {
	TTL time.Duration `yaml:"ttl"`
}

type UpstreamTLS struct {
	CAFile string `yaml:"ca_file"`
}

type Route struct {
	Name     string `yaml:"name"`
	Upstream string `yaml:"upstream"`
	// AllowInsecureUpstream permits a plain-http upstream (credential sent in
	// cleartext). Intended only for isolated demo networks.
	AllowInsecureUpstream bool     `yaml:"allow_insecure_upstream"`
	Secret                Secret   `yaml:"secret"`
	Inject                Inject   `yaml:"inject"`
	Allow                 []string `yaml:"allow"`
}

type Secret struct {
	Mount string `yaml:"mount"`
	Path  string `yaml:"path"`
	Key   string `yaml:"key"`
}

type Inject struct {
	Header string   `yaml:"header"`
	Prefix *string  `yaml:"prefix"`
	Strip  []string `yaml:"strip"`
}

// Load reads and validates a config file. Unknown keys are rejected.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return Parse(b)
}

// Parse decodes and validates YAML.
func Parse(b []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = ":8443"
	}
	if c.Vault.Timeout == 0 {
		c.Vault.Timeout = 5 * time.Second
	}
	if c.Vault.AppRole.Mount == "" {
		c.Vault.AppRole.Mount = "approle"
	}
	if c.Cache.TTL == 0 {
		c.Cache.TTL = 60 * time.Second
	}
}

func (c *Config) validate() error {
	var errs []error
	if c.TLS.CertFile == "" || c.TLS.KeyFile == "" || c.TLS.ClientCAFile == "" {
		errs = append(errs, errors.New("tls.cert_file, tls.key_file and tls.client_ca_file are required"))
	}
	if c.Vault.Address == "" {
		errs = append(errs, errors.New("vault.address is required"))
	}
	if c.Vault.AppRole.RoleIDFile == "" || c.Vault.AppRole.SecretIDFile == "" {
		errs = append(errs, errors.New("vault.approle.role_id_file and secret_id_file are required"))
	}
	if len(c.Routes) == 0 {
		errs = append(errs, errors.New("at least one route is required"))
	}
	if _, err := c.CoreRoutes(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// CoreRoutes converts route definitions into validated core routes.
func (c *Config) CoreRoutes() ([]*core.Route, error) {
	seen := map[string]bool{}
	out := make([]*core.Route, 0, len(c.Routes))
	for _, r := range c.Routes {
		if seen[r.Name] {
			return nil, fmt.Errorf("duplicate route %q", r.Name)
		}
		seen[r.Name] = true
		u, err := url.Parse(r.Upstream)
		if err != nil {
			return nil, fmt.Errorf("route %q: invalid upstream", r.Name)
		}
		if u.Scheme == "http" && !r.AllowInsecureUpstream {
			return nil, fmt.Errorf("route %q: plain-http upstream requires allow_insecure_upstream: true", r.Name)
		}
		header := r.Inject.Header
		prefix := ""
		if header == "" {
			header = "Authorization"
		}
		if r.Inject.Prefix != nil {
			prefix = *r.Inject.Prefix
		} else if header == "Authorization" {
			prefix = "Bearer "
		}
		allow := make([]core.WorkloadID, 0, len(r.Allow))
		for _, a := range r.Allow {
			id, err := core.ParseWorkloadID(a)
			if err != nil {
				return nil, fmt.Errorf("route %q: %w", r.Name, err)
			}
			allow = append(allow, id)
		}
		cr := &core.Route{
			Name:     r.Name,
			Upstream: u,
			Secret:   core.SecretRef{Mount: r.Secret.Mount, Path: r.Secret.Path, Key: r.Secret.Key},
			Inject:   core.InjectRule{Header: header, Prefix: prefix, Strip: r.Inject.Strip},
			Allow:    allow,
		}
		if err := cr.Validate(); err != nil {
			return nil, err
		}
		out = append(out, cr)
	}
	return out, nil
}
