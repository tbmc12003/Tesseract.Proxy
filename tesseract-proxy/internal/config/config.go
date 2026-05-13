// Package config parses and validates the operator-owned proxy configuration
// (proxy.conf.yaml). See docs/equinomics.arch.md §13.8 for the source-of-truth
// schema.
//
// The operator config is unsigned, owned by the BYOC user, and describes
// deployment shape: listen addresses, mTLS cert paths, bundle source,
// idempotency budget, audit log destination, and logging.
//
// Parsing is strict: unknown fields are rejected. Validation rules are
// enforced at construction; callers receive a fully-formed Config or an
// error — never a partially-valid one.
package config

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the operator configuration. Field order mirrors the example in
// arch §13.8.
type Config struct {
	Listen        Listen        `yaml:"listen"`
	MTLS          MTLS          `yaml:"mtls"`
	ProfileBundle ProfileBundle `yaml:"profile_bundle"`
	AuditLog      AuditLog      `yaml:"audit_log"`
	Log           Log           `yaml:"log"`
	// Binary is optional; absent → /admin/binary/upload returns 501.
	Binary Binary `yaml:"binary,omitempty"`
	// Egress is optional; absent or enabled=false → no in-process
	// firewall management (useful on dev hosts without nftables).
	Egress Egress `yaml:"egress,omitempty"`
}

// Listen holds the bind addresses. order_plane is mandatory; admin_plane is
// optional — when omitted, admin endpoints are muxed onto the order-plane
// listener under /admin/* (arch §14.1).
type Listen struct {
	OrderPlane string `yaml:"order_plane"`
	AdminPlane string `yaml:"admin_plane,omitempty"`
}

// MTLS holds the server cert / key / client-CA paths and the initial
// serial allowlists. Serials can be rotated at runtime via
// POST /admin/client-serials (P2.10) — this config is only the bootstrap
// state.
type MTLS struct {
	ServerCert          string   `yaml:"server_cert"`
	ServerKey           string   `yaml:"server_key"`
	ClientCA            string   `yaml:"client_ca"`
	AllowedOrderSerials []string `yaml:"allowed_order_serials,omitempty"`
	AllowedAdminSerials []string `yaml:"allowed_admin_serials,omitempty"`
}

// ProfileBundle describes where to find the signed broker bundle and (if
// enabled) how to refresh it.
type ProfileBundle struct {
	Path       string  `yaml:"path"`
	SigPath    string  `yaml:"sig_path"`
	PubkeyPath string  `yaml:"pubkey_path"`
	Refresh    Refresh `yaml:"refresh"`
}

// Refresh controls the background bundle-update poller.
type Refresh struct {
	Enabled  bool     `yaml:"enabled"`
	URL      string   `yaml:"url,omitempty"`
	Interval Duration `yaml:"interval,omitempty"`
}

// AuditLog configures the structured-log audit sink.
type AuditLog struct {
	Path        string `yaml:"path"`
	RotationMB  int    `yaml:"rotation_mb"`
	RetainCount int    `yaml:"retain_count"`
}

// Log configures the operational logger (slog). Values map directly to
// internal/log.Options.
type Log struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// Binary describes where the binary self-update receiver stages and
// promotes new builds (P2.12). All paths are required when the block is
// present; omitting the block disables the upload endpoint entirely.
type Binary struct {
	CurrentPath  string `yaml:"current_path"`
	PreviousPath string `yaml:"previous_path"`
	StagedPath   string `yaml:"staged_path"`
	PubkeyPath   string `yaml:"pubkey_path"`
}

// IsZero reports whether no fields were set — used by the loader to
// distinguish "binary block omitted" from "binary block present but
// invalid".
func (b Binary) IsZero() bool {
	return b.CurrentPath == "" && b.PreviousPath == "" && b.StagedPath == "" && b.PubkeyPath == ""
}

// Egress configures the in-process nftables-egress generator (P2.13).
// Enabled defaults to false because the dev host typically has no
// nftables; production turns it on.
type Egress struct {
	Enabled    bool     `yaml:"enabled"`
	Refresh    Duration `yaml:"refresh,omitempty"`
	NftPath    string   `yaml:"nft_path,omitempty"`
	HelperPath string   `yaml:"helper_path,omitempty"`
}

// Load reads, parses, and validates a config file at the given path.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: open %s: %w", path, err)
	}
	defer f.Close()

	cfg, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	return cfg, nil
}

// Parse reads YAML from r, decodes it strictly (unknown fields rejected),
// and validates the result.
func Parse(r io.Reader) (*Config, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}

	// Guard against trailing documents — operator config is a single doc.
	var tail any
	if err := dec.Decode(&tail); err == nil {
		return nil, fmt.Errorf("parse yaml: unexpected additional document")
	} else if err != io.EOF {
		return nil, fmt.Errorf("parse yaml (trailing): %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate enforces structural and semantic rules on a Config. It does not
// touch the filesystem — file existence is verified by the runtime that
// actually opens the cert / bundle.
func (c *Config) Validate() error {
	if err := c.Listen.validate(); err != nil {
		return err
	}
	if err := c.MTLS.validate(); err != nil {
		return err
	}
	if err := c.ProfileBundle.validate(); err != nil {
		return err
	}
	if err := c.AuditLog.validate(); err != nil {
		return err
	}
	if err := c.Log.validate(); err != nil {
		return err
	}
	if err := c.Binary.validate(); err != nil {
		return err
	}
	if err := c.Egress.validate(); err != nil {
		return err
	}
	return nil
}

// ListenChanged reports whether the listen-block differs from other. Used by
// the SIGHUP reload path: listener changes require a process restart and
// cannot be applied via hot reload.
func (c *Config) ListenChanged(other *Config) bool {
	return c.Listen != other.Listen
}

func (l *Listen) validate() error {
	if l.OrderPlane == "" {
		return fmt.Errorf("listen.order_plane: required")
	}
	if err := validateHostPort(l.OrderPlane); err != nil {
		return fmt.Errorf("listen.order_plane: %w", err)
	}
	if l.AdminPlane != "" {
		if err := validateHostPort(l.AdminPlane); err != nil {
			return fmt.Errorf("listen.admin_plane: %w", err)
		}
	}
	return nil
}

func (m *MTLS) validate() error {
	for name, v := range map[string]string{
		"mtls.server_cert": m.ServerCert,
		"mtls.server_key":  m.ServerKey,
		"mtls.client_ca":   m.ClientCA,
	} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("%s: required", name)
		}
	}
	if len(m.AllowedOrderSerials)+len(m.AllowedAdminSerials) == 0 {
		return fmt.Errorf("mtls: at least one allowed serial (order or admin) is required")
	}
	return nil
}

func (p *ProfileBundle) validate() error {
	for name, v := range map[string]string{
		"profile_bundle.path":        p.Path,
		"profile_bundle.sig_path":    p.SigPath,
		"profile_bundle.pubkey_path": p.PubkeyPath,
	} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("%s: required", name)
		}
	}
	return p.Refresh.validate()
}

func (r *Refresh) validate() error {
	if !r.Enabled {
		return nil
	}
	if r.URL == "" {
		return fmt.Errorf("profile_bundle.refresh.url: required when refresh.enabled")
	}
	u, err := url.Parse(r.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("profile_bundle.refresh.url: must be a valid http(s) URL, got %q", r.URL)
	}
	if time.Duration(r.Interval) <= 0 {
		return fmt.Errorf("profile_bundle.refresh.interval: must be > 0 when refresh.enabled")
	}
	return nil
}

func (a *AuditLog) validate() error {
	if strings.TrimSpace(a.Path) == "" {
		return fmt.Errorf("audit_log.path: required")
	}
	if a.RotationMB <= 0 {
		return fmt.Errorf("audit_log.rotation_mb: must be > 0")
	}
	if a.RetainCount <= 0 {
		return fmt.Errorf("audit_log.retain_count: must be > 0")
	}
	return nil
}

func (b *Binary) validate() error {
	if b.IsZero() {
		return nil // optional block; upload endpoint will return 501
	}
	for name, v := range map[string]string{
		"binary.current_path":  b.CurrentPath,
		"binary.previous_path": b.PreviousPath,
		"binary.staged_path":   b.StagedPath,
		"binary.pubkey_path":   b.PubkeyPath,
	} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("%s: required when binary block is present", name)
		}
	}
	return nil
}

func (e *Egress) validate() error {
	if !e.Enabled {
		return nil
	}
	if time.Duration(e.Refresh) <= 0 {
		return fmt.Errorf("egress.refresh: required and > 0 when egress.enabled")
	}
	if e.NftPath == "" && e.HelperPath == "" {
		return fmt.Errorf("egress: one of nft_path or helper_path is required when egress.enabled")
	}
	return nil
}

func (l *Log) validate() error {
	switch strings.ToLower(strings.TrimSpace(l.Level)) {
	case "", "debug", "info", "warn", "warning", "error":
	default:
		return fmt.Errorf("log.level: unknown %q (want debug|info|warn|error)", l.Level)
	}
	switch strings.ToLower(strings.TrimSpace(l.Format)) {
	case "", "json", "text":
	default:
		return fmt.Errorf("log.format: unknown %q (want json|text)", l.Format)
	}
	return nil
}

func validateHostPort(s string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("invalid host:port %q: %w", s, err)
	}
	if port == "" {
		return fmt.Errorf("invalid host:port %q: port is empty", s)
	}
	// host may be empty (binds all interfaces), "0.0.0.0", "127.0.0.1", an
	// IPv6 literal, or a hostname; we accept any non-error split.
	_ = host
	return nil
}

// Duration is a yaml-decodable wrapper around time.Duration. It accepts any
// string parseable by time.ParseDuration (e.g. "120s", "6h", "500ms").
type Duration time.Duration

// UnmarshalYAML decodes a string node into a Duration.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a string: %w", err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// Std returns the underlying time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }
