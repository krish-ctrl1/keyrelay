// Command keyrelay-proxy runs the KeyRelay mTLS credential relay.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/keyrelay/keyrelay/internal/config"
	"github.com/keyrelay/keyrelay/internal/core"
	"github.com/keyrelay/keyrelay/internal/proxy"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "keyrelay:", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := flag.String("config", "/etc/keyrelay/config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	vaultHTTP := &http.Client{Timeout: cfg.Vault.Timeout}
	if cfg.Vault.CAFile != "" {
		pem, err := os.ReadFile(cfg.Vault.CAFile)
		if err != nil {
			return fmt.Errorf("vault ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return errors.New("vault ca: no certificates")
		}
		vaultHTTP.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	}
	vault, err := core.NewVaultProvider(core.VaultConfig{
		Address:      cfg.Vault.Address,
		Namespace:    cfg.Vault.Namespace,
		AppRoleMount: cfg.Vault.AppRole.Mount,
		RoleIDFile:   cfg.Vault.AppRole.RoleIDFile,
		SecretIDFile: cfg.Vault.AppRole.SecretIDFile,
		HTTPClient:   vaultHTTP,
	})
	if err != nil {
		return err
	}
	routes, err := cfg.CoreRoutes()
	if err != nil {
		return err
	}
	engine, err := core.NewEngine(routes, core.NewCachingProvider(vault, cfg.Cache.TTL))
	if err != nil {
		return err
	}
	transport, err := proxy.LoadUpstreamTransport(cfg.UpstreamTLS.CAFile)
	if err != nil {
		return err
	}
	handler, err := proxy.New(proxy.Options{Engine: engine, Auditor: core.NewAuditor(os.Stdout), Transport: transport})
	if err != nil {
		return err
	}
	tlsCfg, err := proxy.ServerTLSConfig(cfg.TLS.CertFile, cfg.TLS.KeyFile, cfg.TLS.ClientCAFile)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          log.New(os.Stderr, "keyrelay-http: ", 0),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() {
		logger.Info("keyrelay listening", "addr", cfg.Listen, "routes", len(routes))
		errc <- srv.ListenAndServeTLS("", "")
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
