// Package binupd verifies and stages a new proxy binary uploaded via the
// admin endpoint, and exposes a Rollback that swaps the previous binary
// back into place (arch §7.0, P2.12).
//
// Process restart is intentionally NOT this package's concern: after
// Apply returns, the caller (cmd/proxy/main.go) is responsible for
// gracefully shutting down the HTTP server and either calling
// `systemctl restart tesseract-proxy` or os.Exit-ing (systemd's
// `Restart=on-failure` covers the rest). Keeping the swap and the
// restart separate lets tests exercise the file-system promotion
// without spawning systemd.
package binupd

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Options configures a Receiver. All paths are required.
type Options struct {
	// PubkeyPath points at a PEM-encoded PKIX Ed25519 public key. This
	// is the *binary* signing pubkey — independent from the bundle
	// signing pubkey, though both may live behind the same KMS in
	// production.
	PubkeyPath string
	// CurrentPath is the live binary path (e.g. /opt/tesseract-proxy/proxy).
	CurrentPath string
	// PreviousPath holds the prior binary for rollback.
	PreviousPath string
	// StagedPath is a sibling path used as the temp landing zone.
	StagedPath string
}

// Receiver applies signed binary uploads.
type Receiver struct {
	opts Options
	pub  ed25519.PublicKey
}

// New constructs a Receiver, loading and validating the pubkey.
func New(opts Options) (*Receiver, error) {
	for name, v := range map[string]string{
		"PubkeyPath": opts.PubkeyPath, "CurrentPath": opts.CurrentPath,
		"PreviousPath": opts.PreviousPath, "StagedPath": opts.StagedPath,
	} {
		if v == "" {
			return nil, fmt.Errorf("binupd: %s is required", name)
		}
	}
	pub, err := readPubkey(opts.PubkeyPath)
	if err != nil {
		return nil, err
	}
	return &Receiver{opts: opts, pub: pub}, nil
}

func readPubkey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("binupd: read pubkey: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("binupd: pubkey: expected PEM PUBLIC KEY block in %s", path)
	}
	anyKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("binupd: pubkey parse: %w", err)
	}
	pub, ok := anyKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("binupd: pubkey is not Ed25519 (got %T)", anyKey)
	}
	return pub, nil
}

// Apply verifies the signature, writes the binary to the staged path with
// mode 0o755, and promotes it (current ⇒ previous, staged ⇒ current).
// On verification or write failure the staged path is cleaned up and the
// current binary is left in place (fail closed).
func (r *Receiver) Apply(binary, signature []byte) error {
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("binupd: signature: expected %d bytes, got %d",
			ed25519.SignatureSize, len(signature))
	}
	if !ed25519.Verify(r.pub, binary, signature) {
		return errors.New("binupd: signature verification failed")
	}
	if err := writeExecutable(r.opts.StagedPath, binary); err != nil {
		return err
	}
	if err := promote(r.opts.CurrentPath, r.opts.StagedPath, r.opts.PreviousPath); err != nil {
		_ = os.Remove(r.opts.StagedPath)
		return err
	}
	return nil
}

// Rollback swaps Current and Previous. It is the implementation behind
// `tesseract-proxy --rollback-binary`. Returns an error if no previous
// binary exists.
func (r *Receiver) Rollback() error {
	if _, err := os.Stat(r.opts.PreviousPath); err != nil {
		return fmt.Errorf("binupd: no previous binary to roll back to: %w", err)
	}
	// Stage the current as a temporary so we don't lose it.
	tmp := r.opts.CurrentPath + ".rollback-tmp"
	if err := os.Rename(r.opts.CurrentPath, tmp); err != nil {
		return fmt.Errorf("binupd: stash current: %w", err)
	}
	if err := os.Rename(r.opts.PreviousPath, r.opts.CurrentPath); err != nil {
		// Try to put current back so we're not left without a binary.
		_ = os.Rename(tmp, r.opts.CurrentPath)
		return fmt.Errorf("binupd: promote previous: %w", err)
	}
	if err := os.Rename(tmp, r.opts.PreviousPath); err != nil {
		return fmt.Errorf("binupd: demote current: %w", err)
	}
	return nil
}

func writeExecutable(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("binupd: create staged: %w", err)
	}
	cleanup := func() { _ = os.Remove(tmp.Name()) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("binupd: write staged: %w", err)
	}
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("binupd: chmod staged: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("binupd: close staged: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		cleanup()
		return fmt.Errorf("binupd: rename staged: %w", err)
	}
	return nil
}

// promote moves current ⇒ previous (overwriting), then staged ⇒ current.
func promote(current, staged, previous string) error {
	if _, err := os.Stat(current); err == nil {
		if err := os.Rename(current, previous); err != nil {
			return fmt.Errorf("binupd: rotate current → previous: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(staged, current); err != nil {
		return fmt.Errorf("binupd: promote staged → current: %w", err)
	}
	return nil
}
