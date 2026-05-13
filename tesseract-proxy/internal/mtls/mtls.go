// Package mtls builds the TLS configuration for the proxy's listener and
// classifies authenticated peers by serial-number allowlist (arch §7.3 /
// §7.5 / §14.1).
//
// Properties enforced at the TLS layer:
//   - TLS 1.3 only (MinVersion = MaxVersion = VersionTLS13).
//   - ALPN advertises "h2" only.
//   - Client cert required and verified against a configured CA.
//   - Client cert serial number must appear in either the order or the
//     admin allowlist; otherwise the handshake is aborted before any
//     application byte is processed.
//
// TLS 1.3 in crypto/tls does not expose cipher-suite negotiation —
// `TLS_AES_256_GCM_SHA384` and `TLS_CHACHA20_POLY1305_SHA256` are the
// negotiated set by construction (Go's TLS 1.3 stack does not enable
// `TLS_AES_128_GCM_SHA256` for clients that request it unless the server
// permits it; we accept Go's defaults rather than fighting them).
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync/atomic"
)

// Role is the authorisation class assigned to an authenticated peer by
// serial-number lookup. A handshake that produces RoleNone is rejected at
// the TLS layer; admin endpoints additionally require RoleAdmin.
type Role uint8

const (
	RoleNone  Role = iota // not allow-listed; reject
	RoleOrder             // order-plane only
	RoleAdmin             // admin-plane (which always includes order-plane access; admin is a superset)
)

// String renders a Role for log lines.
func (r Role) String() string {
	switch r {
	case RoleOrder:
		return "order"
	case RoleAdmin:
		return "admin"
	default:
		return "none"
	}
}

// Allows reports whether r is permitted to access endpoints requiring the
// given minimum role.
func (r Role) Allows(min Role) bool {
	return r >= min && r != RoleNone
}

// Options is the input to BuildServerConfig. All file paths are read once
// at construction; subsequent rotation goes through a different code path
// (admin endpoint /admin/cert/rotate-server, P2.10 / §7.7).
type Options struct {
	ServerCertPath string
	ServerKeyPath  string
	ClientCAPath   string
	// AllowedOrderSerials and AllowedAdminSerials are decimal- or
	// hex-string-encoded big.Int serial numbers. Both lists are
	// independent; a serial may appear in admin without appearing in
	// order — admin is a strict superset.
	AllowedOrderSerials []string
	AllowedAdminSerials []string
}

// Allowlist is the live, atomic, role-classifying serial table. It supports
// in-place updates from the /admin/client-serials endpoint (P2.10) without
// rebuilding the TLS config.
type Allowlist struct {
	order atomic.Pointer[serialSet]
	admin atomic.Pointer[serialSet]
}

type serialSet map[string]struct{} // key: serial.Text(10)

// NewAllowlist constructs an Allowlist from the configured Options.
func NewAllowlist(opts Options) (*Allowlist, error) {
	order, err := parseSerials(opts.AllowedOrderSerials)
	if err != nil {
		return nil, fmt.Errorf("mtls: order serials: %w", err)
	}
	admin, err := parseSerials(opts.AllowedAdminSerials)
	if err != nil {
		return nil, fmt.Errorf("mtls: admin serials: %w", err)
	}
	if len(order) == 0 && len(admin) == 0 {
		return nil, errors.New("mtls: at least one allowed serial is required")
	}
	a := &Allowlist{}
	a.order.Store(&order)
	a.admin.Store(&admin)
	return a, nil
}

// Classify reports the Role for a presented serial. Admin classification
// takes precedence over order.
func (a *Allowlist) Classify(serial *big.Int) Role {
	if serial == nil {
		return RoleNone
	}
	key := serial.Text(10)
	if s := a.admin.Load(); s != nil {
		if _, ok := (*s)[key]; ok {
			return RoleAdmin
		}
	}
	if s := a.order.Load(); s != nil {
		if _, ok := (*s)[key]; ok {
			return RoleOrder
		}
	}
	return RoleNone
}

// Replace atomically swaps in new order/admin serial sets. Used by the
// admin endpoint (P2.10) when client-cert rotation publishes new serials.
func (a *Allowlist) Replace(orderSerials, adminSerials []string) error {
	order, err := parseSerials(orderSerials)
	if err != nil {
		return fmt.Errorf("mtls: order serials: %w", err)
	}
	admin, err := parseSerials(adminSerials)
	if err != nil {
		return fmt.Errorf("mtls: admin serials: %w", err)
	}
	a.order.Store(&order)
	a.admin.Store(&admin)
	return nil
}

func parseSerials(in []string) (serialSet, error) {
	out := make(serialSet, len(in))
	for _, s := range in {
		n, ok := new(big.Int).SetString(s, 0)
		if !ok {
			return nil, fmt.Errorf("invalid serial %q", s)
		}
		if n.Sign() <= 0 {
			return nil, fmt.Errorf("serial must be positive: %q", s)
		}
		out[n.Text(10)] = struct{}{}
	}
	return out, nil
}

// BuildServerConfig produces a *tls.Config suitable for binding the order
// + admin listener. It loads the server cert/key and CA pool, sets
// TLS 1.3-only, requires a client cert, and installs a VerifyConnection
// callback that consults the Allowlist.
func BuildServerConfig(opts Options) (*tls.Config, *Allowlist, error) {
	cert, err := tls.LoadX509KeyPair(opts.ServerCertPath, opts.ServerKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("mtls: load server keypair: %w", err)
	}
	caPEM, err := os.ReadFile(opts.ClientCAPath)
	if err != nil {
		return nil, nil, fmt.Errorf("mtls: read client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, nil, fmt.Errorf("mtls: client CA %s contained no usable certificates", opts.ClientCAPath)
	}

	allowlist, err := NewAllowlist(opts)
	if err != nil {
		return nil, nil, err
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		NextProtos:   []string{"h2"},

		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("mtls: no client certificate presented")
			}
			peer := cs.PeerCertificates[0]
			role := allowlist.Classify(peer.SerialNumber)
			if role == RoleNone {
				return fmt.Errorf("mtls: client serial %s not in allowlist", peer.SerialNumber.Text(10))
			}
			return nil
		},
	}
	return cfg, allowlist, nil
}

// PeerRole inspects an already-verified *tls.ConnectionState and reports
// the authenticated peer's role. Used by handler middleware to gate
// /admin/*. Returns RoleNone if no client cert is present (which should
// not happen if BuildServerConfig produced the listener).
func PeerRole(allowlist *Allowlist, cs *tls.ConnectionState) Role {
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return RoleNone
	}
	return allowlist.Classify(cs.PeerCertificates[0].SerialNumber)
}
