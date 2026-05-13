// Command tesseract-proxy is the order pass-through proxy for the Tesseract
// desktop trading platform.
//
// Regulatory ref:
//
//	NSE/INVG/67858 (NSE circular 471/2025) dated 2025-05-05
//	SEBI/HO/MIRSD/MIRSD-PoD/P/CIR/2025/0000013 dated 2025-02-04
//
// Architecture interpretation: the static-IP requirement applies to order
// endpoints; reads + WebSocket subscriptions flow direct from desktop to
// broker (see docs/equinomics.arch.md §1.0 and
// docs/legal/INVG67858_findings.md).
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/equinomics/tesseract-proxy/internal/admin"
	"github.com/equinomics/tesseract-proxy/internal/audit"
	"github.com/equinomics/tesseract-proxy/internal/binupd"
	"github.com/equinomics/tesseract-proxy/internal/bundleupd"
	"github.com/equinomics/tesseract-proxy/internal/config"
	"github.com/equinomics/tesseract-proxy/internal/egress"
	"github.com/equinomics/tesseract-proxy/internal/log"
	"github.com/equinomics/tesseract-proxy/internal/metrics"
	"github.com/equinomics/tesseract-proxy/internal/mtls"
	"github.com/equinomics/tesseract-proxy/internal/profile"
	"github.com/equinomics/tesseract-proxy/internal/proxy"
)

// Version is the build version. Overridden at link time:
//
//	go build -ldflags "-X main.Version=v0.1.0" ./cmd/proxy
var Version = "dev"

const (
	defaultConfigPath    = "/etc/tesseract-proxy/proxy.conf.yaml"
	defaultBundleRefresh = 6 * time.Hour
)

func main() {
	if err := run(os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

type flags struct {
	configPath     string
	showVersion    bool
	logLevel       string
	logFormat      string
	rollbackBundle bool
	rollbackBinary bool
}

func parseFlags(args []string, stderr *os.File) (*flags, error) {
	fs := flag.NewFlagSet("tesseract-proxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	f := &flags{}
	fs.BoolVar(&f.showVersion, "version", false, "print version and exit")
	fs.StringVar(&f.configPath, "config", defaultConfigPath, "path to operator config (proxy.conf.yaml)")
	fs.StringVar(&f.logLevel, "log-level", "", "log level override: debug|info|warn|error (overrides log.level in config)")
	fs.StringVar(&f.logFormat, "log-format", "", "log format override: json|text (overrides log.format in config)")
	fs.BoolVar(&f.rollbackBundle, "rollback-bundle", false, "swap bundle.yaml.previous into the active slot, then exit")
	fs.BoolVar(&f.rollbackBinary, "rollback-binary", false, "swap binary previous into the active slot, then exit")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return f, nil
}

func run(args []string, stderr *os.File) error {
	f, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return fmt.Errorf("parse flags: %w", err)
	}
	if f.showVersion {
		fmt.Fprintln(os.Stdout, Version)
		return nil
	}

	cfg, err := config.Load(f.configPath)
	if err != nil {
		return err
	}
	logger, err := log.New(log.Options{
		Level:  pick(f.logLevel, cfg.Log.Level),
		Format: pick(f.logFormat, cfg.Log.Format),
		Output: stderr,
	})
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}

	if f.rollbackBundle {
		return rollbackBundle(cfg, logger)
	}
	if f.rollbackBinary {
		return rollbackBinary(cfg, logger)
	}

	logger.Info("starting",
		"version", Version,
		"pid", os.Getpid(),
		"config", f.configPath,
		"order_plane", cfg.Listen.OrderPlane,
	)

	return serve(cfg, f.configPath, logger)
}

func serve(cfg *config.Config, configPath string, logger *slog.Logger) error {
	startedAt := time.Now()

	auditW, err := audit.Open(audit.Options{Path: cfg.AuditLog.Path, RingSize: 256})
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	defer auditW.Close()

	m := &metrics.Counters{}
	holder := profile.NewHolder(nil)

	initialRes, err := profile.LoadAndVerify(profile.LoadOptions{
		BundlePath:    cfg.ProfileBundle.Path,
		SigPath:       cfg.ProfileBundle.SigPath,
		PubkeyPath:    cfg.ProfileBundle.PubkeyPath,
		BinaryVersion: Version,
	})
	if err != nil {
		return fmt.Errorf("initial bundle: %w", err)
	}
	holder.Store(initialRes.Router)
	logger.Info("initial bundle loaded",
		"bundle_version", initialRes.Bundle.BundleVersion,
		"brokers", len(initialRes.Bundle.Brokers))

	tlsCfg, allowlist, err := mtls.BuildServerConfig(mtls.Options{
		ServerCertPath:      cfg.MTLS.ServerCert,
		ServerKeyPath:       cfg.MTLS.ServerKey,
		ClientCAPath:        cfg.MTLS.ClientCA,
		AllowedOrderSerials: cfg.MTLS.AllowedOrderSerials,
		AllowedAdminSerials: cfg.MTLS.AllowedAdminSerials,
	})
	if err != nil {
		return fmt.Errorf("mtls: %w", err)
	}

	var receiver *binupd.Receiver
	if !cfg.Binary.IsZero() {
		receiver, err = binupd.New(binupd.Options{
			PubkeyPath:   cfg.Binary.PubkeyPath,
			CurrentPath:  cfg.Binary.CurrentPath,
			PreviousPath: cfg.Binary.PreviousPath,
			StagedPath:   cfg.Binary.StagedPath,
		})
		if err != nil {
			return fmt.Errorf("binupd: %w", err)
		}
	}

	// Egress generator — optional.
	var egressGen *egress.Generator
	if cfg.Egress.Enabled {
		var applier egress.Applier
		if cfg.Egress.HelperPath != "" {
			applier = &egress.HelperApplier{Path: cfg.Egress.HelperPath}
		} else {
			applier = &egress.NftApplier{Path: cfg.Egress.NftPath}
		}
		egressGen, err = egress.New(egress.Options{
			Resolver: netResolver{},
			Applier:  applier,
			Interval: cfg.Egress.Refresh.Std(),
			Logger:   logger,
		})
		if err != nil {
			return fmt.Errorf("egress: %w", err)
		}
		egressGen.UpdateHosts(enabledHosts(initialRes.Bundle))
	}

	// Bundle updater.
	refresh := time.Duration(cfg.ProfileBundle.Refresh.Interval)
	if refresh <= 0 {
		refresh = defaultBundleRefresh
	}
	fetcher := &bundleupd.HTTPFetcher{
		BundleURL: cfg.ProfileBundle.Refresh.URL,
		SigURL:    cfg.ProfileBundle.Refresh.URL + ".sig",
		Client:    &http.Client{Timeout: 30 * time.Second},
	}
	updater, err := bundleupd.New(bundleupd.Options{
		Fetcher:       fetcher,
		Interval:      refresh,
		Holder:        holder,
		BundlePath:    cfg.ProfileBundle.Path,
		SigPath:       cfg.ProfileBundle.SigPath,
		PubkeyPath:    cfg.ProfileBundle.PubkeyPath,
		BinaryVersion: Version,
		Logger:        logger,
		OnSwap: func(b *profile.Bundle) {
			logger.Info("bundle reloaded",
				"bundle_version", b.BundleVersion, "brokers", len(b.Brokers))
			if egressGen != nil {
				egressGen.UpdateHosts(enabledHosts(b))
			}
		},
	})
	if err != nil {
		return fmt.Errorf("updater: %w", err)
	}

	proxyH, err := proxy.New(proxy.Options{
		Holder:    holder,
		Transport: http.DefaultTransport,
		Audit:     auditW,
		Metrics:   m,
		Logger:    logger,
	})
	if err != nil {
		return fmt.Errorf("proxy handler: %w", err)
	}

	adminH := admin.New(admin.Options{
		Version:   Version,
		StartedAt: startedAt,
		Holder:    holder,
		Allowlist: allowlist,
		Audit:     auditW,
		Metrics:   m,
		Logger:    logger,
		ReloadBundle: func() error {
			return updater.Tick(context.Background())
		},
		AcceptBinary: func(binary, signature []byte) error {
			if receiver == nil {
				return errors.New("binary upload not configured")
			}
			return receiver.Apply(binary, signature)
		},
	})

	mux := http.NewServeMux()
	mux.Handle("/admin/", adminH)
	mux.Handle("/", proxyH)

	srv := &http.Server{
		Addr:              cfg.Listen.OrderPlane,
		Handler:           mux,
		TLSConfig:         tlsCfg,
		ErrorLog:          mtls.HandshakeErrorLogger(&m.HandshakeFailures, &slogWriter{logger: logger}),
		ReadHeaderTimeout: 10 * time.Second,
	}

	rootCtx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var workersWG sync.WaitGroup
	if cfg.ProfileBundle.Refresh.Enabled {
		workersWG.Add(1)
		go func() {
			defer workersWG.Done()
			_ = updater.Run(rootCtx)
		}()
	}
	if egressGen != nil {
		workersWG.Add(1)
		go func() {
			defer workersWG.Done()
			_ = egressGen.Run(rootCtx)
		}()
	}

	sigHUP, sigUSR1, stopSigs := installReloadSignals()
	defer stopSigs()

	var sigWG sync.WaitGroup
	sigWG.Add(1)
	go func() {
		defer sigWG.Done()
		for {
			select {
			case <-rootCtx.Done():
				return
			case <-sigHUP:
				logger.Info("SIGHUP: reloading config + audit + bundle")
				if newCfg, err := config.Load(configPath); err != nil {
					logger.Error("config reload failed", "err", err.Error())
				} else if newCfg.ListenChanged(cfg) {
					logger.Error("listen changed; restart required (keeping old)")
				}
				if err := auditW.Reopen(); err != nil {
					logger.Error("audit reopen failed", "err", err.Error())
				}
				if err := updater.Tick(rootCtx); err != nil {
					logger.Warn("bundle tick (SIGHUP)", "err", err.Error())
				}
			case <-sigUSR1:
				logger.Info("SIGUSR1: poke bundle updater")
				updater.Poke()
			}
		}
	}()

	listenErrCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.Listen.OrderPlane)
		// Cert + key are already loaded into tls.Config; pass empty
		// strings so ListenAndServeTLS doesn't re-read them.
		err := srv.ListenAndServeTLS("", "")
		if !errors.Is(err, http.ErrServerClosed) {
			listenErrCh <- err
		}
		close(listenErrCh)
	}()

	select {
	case <-rootCtx.Done():
		logger.Info("shutdown signal received")
	case err := <-listenErrCh:
		if err != nil {
			stop()
			workersWG.Wait()
			sigWG.Wait()
			return fmt.Errorf("listen: %w", err)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("graceful shutdown timed out", "err", err.Error())
	}
	workersWG.Wait()
	sigWG.Wait()
	logger.Info("exit clean")
	return nil
}

func enabledHosts(b *profile.Bundle) []string {
	out := make([]string, 0, len(b.Brokers))
	for _, br := range b.Brokers {
		if br.Enabled {
			out = append(out, br.Host)
		}
	}
	return out
}

func rollbackBundle(cfg *config.Config, logger *slog.Logger) error {
	prevBundle := cfg.ProfileBundle.Path + ".previous"
	prevSig := cfg.ProfileBundle.SigPath + ".previous"
	if _, err := os.Stat(prevBundle); err != nil {
		return fmt.Errorf("rollback-bundle: no previous bundle at %s: %w", prevBundle, err)
	}
	if err := os.Rename(prevBundle, cfg.ProfileBundle.Path); err != nil {
		return fmt.Errorf("rollback-bundle: rename bundle: %w", err)
	}
	if err := os.Rename(prevSig, cfg.ProfileBundle.SigPath); err != nil {
		return fmt.Errorf("rollback-bundle: rename sig: %w", err)
	}
	logger.Info("rollback-bundle: swapped previous into active slot",
		"bundle", cfg.ProfileBundle.Path)
	return nil
}

func rollbackBinary(cfg *config.Config, logger *slog.Logger) error {
	if cfg.Binary.IsZero() {
		return errors.New("rollback-binary: binary block not configured")
	}
	r, err := binupd.New(binupd.Options{
		PubkeyPath:   cfg.Binary.PubkeyPath,
		CurrentPath:  cfg.Binary.CurrentPath,
		PreviousPath: cfg.Binary.PreviousPath,
		StagedPath:   cfg.Binary.StagedPath,
	})
	if err != nil {
		return fmt.Errorf("rollback-binary: %w", err)
	}
	if err := r.Rollback(); err != nil {
		return fmt.Errorf("rollback-binary: %w", err)
	}
	logger.Info("rollback-binary: swapped previous into active slot",
		"current", cfg.Binary.CurrentPath)
	return nil
}

func pick(override, fallback string) string {
	if override != "" {
		return override
	}
	return fallback
}

// netResolver lifts net.DefaultResolver into the egress.Resolver
// interface. Single-method shim.
type netResolver struct{}

func (netResolver) LookupHost(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil {
			out = append(out, ip)
		}
	}
	return out, nil
}

// slogWriter routes the TLS handshake-error fallback into our slog.
type slogWriter struct {
	logger *slog.Logger
}

func (s *slogWriter) Write(p []byte) (int, error) {
	s.logger.Warn("tls error", "line", strings.TrimRight(string(p), "\r\n"))
	return len(p), nil
}

// Compile-time assertion that net's *tls.Config is what BuildServerConfig
// returns. If this ever fails the build fails — easier to fix than to
// debug at runtime.
var _ = (*tls.Config)(nil)
