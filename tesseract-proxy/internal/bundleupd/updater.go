// Package bundleupd polls the bundle CDN, verifies signatures, and swaps
// the live Router on success (arch §13.5).
//
// Lifecycle:
//
//  1. A goroutine ticks every Interval and on Poke() (operator override,
//     SIGUSR1 in production wiring).
//  2. Fetch a candidate bundle from the configured Fetcher. ETag /
//     If-None-Match short-circuits steady-state.
//  3. If the candidate hash matches the last loaded bundle, skip.
//  4. Write bundle + signature to *.staged.
//  5. profile.LoadAndVerify on the staged files (signature, schema,
//     min_proxy_version gate, monotonic bundle_version gate).
//  6. On verify failure: delete staged, log, leave running router intact
//     (fail closed per arch §13.4).
//  7. On verify success: rename current ⇒ *.previous, staged ⇒ current,
//     atomic Holder.Store, optional rate-limit refresh and OnSwap hook.
//
// All-or-nothing: the goroutine never publishes a half-loaded router.
// The previous bundle on disk is retained for rollback (P6.8).
package bundleupd

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/equinomics/tesseract-proxy/internal/profile"
)

// FetchResult is the output of one Fetch call. NotModified == true means
// the server returned 304; Bundle and Signature are then nil.
type FetchResult struct {
	NotModified bool
	Bundle      []byte
	Signature   []byte
	ETag        string
}

// Fetcher is what the Updater asks for a candidate bundle. The HTTPFetcher
// in this package is the production impl; tests inject a stub.
type Fetcher interface {
	Fetch(ctx context.Context, lastETag string) (*FetchResult, error)
}

// Options configures an Updater. Holder, Fetcher, Interval, BundlePath,
// SigPath, PubkeyPath are required; the rest default safely.
type Options struct {
	Fetcher       Fetcher
	Interval      time.Duration
	Holder        *profile.Holder
	BundlePath    string
	SigPath       string
	PubkeyPath    string
	BinaryVersion string
	// OnSwap, when non-nil, is called with the newly-loaded Bundle after
	// the Router has been published. Used by cmd/proxy/main.go to wire
	// audit-log "bundle reload" entries.
	OnSwap func(*profile.Bundle)
	Logger *slog.Logger
}

// Updater is a long-lived polling worker. Construct with New, drive with
// Run, and trigger an immediate fetch with Poke.
type Updater struct {
	opts Options

	mu       sync.Mutex
	lastETag string
	lastHash [32]byte

	poke chan struct{}
}

// New constructs an Updater, validating required Options.
func New(opts Options) (*Updater, error) {
	if opts.Fetcher == nil {
		return nil, errors.New("bundleupd: Fetcher is required")
	}
	if opts.Holder == nil {
		return nil, errors.New("bundleupd: Holder is required")
	}
	if opts.Interval <= 0 {
		return nil, errors.New("bundleupd: Interval must be > 0")
	}
	if opts.BundlePath == "" || opts.SigPath == "" || opts.PubkeyPath == "" {
		return nil, errors.New("bundleupd: BundlePath, SigPath, PubkeyPath all required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Updater{opts: opts, poke: make(chan struct{}, 1)}, nil
}

// Poke schedules an immediate fetch. Idempotent if a pending poke already
// exists. Returns immediately.
func (u *Updater) Poke() {
	select {
	case u.poke <- struct{}{}:
	default:
	}
}

// Run drives the polling loop until ctx is cancelled. Errors from Tick are
// logged and the loop continues; a single bad poll never kills the worker.
func (u *Updater) Run(ctx context.Context) error {
	ticker := time.NewTicker(u.opts.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		case <-u.poke:
		}
		if err := u.Tick(ctx); err != nil {
			u.opts.Logger.Warn("bundle poll failed; keeping current",
				"err", err.Error())
		}
	}
}

// Tick performs one fetch + verify + swap attempt synchronously. It is
// also the entry point /admin/bundle/reload should call.
func (u *Updater) Tick(ctx context.Context) error {
	u.mu.Lock()
	lastETag := u.lastETag
	lastHash := u.lastHash
	u.mu.Unlock()

	res, err := u.opts.Fetcher.Fetch(ctx, lastETag)
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	if res.NotModified {
		return nil
	}
	if len(res.Bundle) == 0 || len(res.Signature) == 0 {
		return errors.New("fetch: empty bundle or signature")
	}
	hash := sha256.Sum256(res.Bundle)
	if hash == lastHash {
		// Content-addressable short-circuit: server may have lost ETag
		// across a CDN flush but content is unchanged.
		u.mu.Lock()
		u.lastETag = res.ETag
		u.mu.Unlock()
		return nil
	}

	stagedBundle := u.opts.BundlePath + ".staged"
	stagedSig := u.opts.SigPath + ".staged"

	if err := writeAtomic(stagedBundle, res.Bundle); err != nil {
		return fmt.Errorf("stage bundle: %w", err)
	}
	if err := writeAtomic(stagedSig, res.Signature); err != nil {
		_ = os.Remove(stagedBundle)
		return fmt.Errorf("stage signature: %w", err)
	}

	var prevVersion string
	if r := u.opts.Holder.Load(); r != nil {
		prevVersion = r.BundleVersion()
	}

	loadRes, err := profile.LoadAndVerify(profile.LoadOptions{
		BundlePath:            stagedBundle,
		SigPath:               stagedSig,
		PubkeyPath:            u.opts.PubkeyPath,
		BinaryVersion:         u.opts.BinaryVersion,
		PreviousBundleVersion: prevVersion,
	})
	if err != nil {
		_ = os.Remove(stagedBundle)
		_ = os.Remove(stagedSig)
		return fmt.Errorf("verify: %w", err)
	}

	if err := promote(u.opts.BundlePath, stagedBundle); err != nil {
		return fmt.Errorf("promote bundle: %w", err)
	}
	if err := promote(u.opts.SigPath, stagedSig); err != nil {
		// Bundle was promoted but sig wasn't — leave a structured log;
		// next reload will heal as the new staged-sig becomes current.
		u.opts.Logger.Error("sig promote failed after bundle promote",
			"err", err.Error())
		return fmt.Errorf("promote sig: %w", err)
	}

	u.opts.Holder.Store(loadRes.Router)

	u.mu.Lock()
	u.lastHash = hash
	u.lastETag = res.ETag
	u.mu.Unlock()

	if u.opts.OnSwap != nil {
		u.opts.OnSwap(loadRes.Bundle)
	}
	return nil
}

// writeAtomic writes data to path via a sibling .tmp file + rename.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return err
	}
	cleanup := func() { _ = os.Remove(tmp.Name()) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		cleanup()
		return err
	}
	return nil
}

// promote moves current ⇒ <current>.previous, then staged ⇒ current.
// On platforms where rename is atomic for same-filesystem moves (POSIX,
// Windows since 1607 with ReplaceFile semantics) the operation is
// crash-safe: at any instant either current or current.previous + staged
// is the consistent state.
func promote(current, staged string) error {
	previous := current + ".previous"
	// If a current exists, rotate it. Missing current is fine (cold start).
	if _, err := os.Stat(current); err == nil {
		if err := os.Rename(current, previous); err != nil {
			return fmt.Errorf("rotate %s → %s: %w", current, previous, err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(staged, current); err != nil {
		return fmt.Errorf("promote %s → %s: %w", staged, current, err)
	}
	return nil
}
