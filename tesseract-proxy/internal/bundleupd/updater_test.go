package bundleupd_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/equinomics/tesseract-proxy/internal/bundleupd"
	"github.com/equinomics/tesseract-proxy/internal/profile"
)

func bundleYAML(version string, rps int) string {
	return fmt.Sprintf(`schema_version: 1
bundle_version: %s
issued_at: 2026-05-13T10:00:00Z
issuer: equinomics
min_proxy_version: 0.4.0
brokers:
  - id: papertrader
    display_name: PaperTrader
    host: papertrader.local
    enabled: true
    order_endpoints:
      - method: POST
        path: /Orders/2.0/quick/order/rule/ms/place
        kind: place
    idempotency:
      client_order_id_header: X-Client-Order-Id
      client_order_id_body_path: ""
      echo_in_response_path: data.orderNumber
    rate_limit:
      per_user_rps: %d
      per_user_burst: 10
`, version, rps)
}

// signingKit holds an ECDSA P-256 keypair and writes the matching pubkey to a
// temp file for the Updater's PubkeyPath. Bundles are signed inline.
type signingKit struct {
	priv       *ecdsa.PrivateKey
	pubkeyPath string
}

func newSigningKit(t *testing.T) *signingKit {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "pubkey.pem")
	if err := os.WriteFile(path,
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return &signingKit{priv: priv, pubkeyPath: path}
}

func (k *signingKit) sign(b []byte) []byte {
	h := sha256.Sum256(b)
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, h[:])
	if err != nil {
		panic(err)
	}
	return sig
}

func signWith(priv *ecdsa.PrivateKey, b []byte) []byte {
	h := sha256.Sum256(b)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		panic(err)
	}
	return sig
}

// stubFetcher returns canned responses in order. After exhaustion it
// returns an error so a misconfigured test surfaces.
type stubFetcher struct {
	mu    atomic.Int64
	calls atomic.Int64
	feed  []func() (*bundleupd.FetchResult, error)
}

func (s *stubFetcher) Fetch(_ context.Context, _ string) (*bundleupd.FetchResult, error) {
	n := s.mu.Add(1) - 1
	s.calls.Add(1)
	if int(n) >= len(s.feed) {
		return nil, fmt.Errorf("stubFetcher: no more responses (call %d)", n)
	}
	return s.feed[n]()
}

type env struct {
	kit        *signingKit
	holder     *profile.Holder
	dir        string
	bundlePath string
	sigPath    string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	kit := newSigningKit(t)
	dir := t.TempDir()
	return &env{
		kit:        kit,
		holder:     profile.NewHolder(nil),
		dir:        dir,
		bundlePath: filepath.Join(dir, "bundle.yaml"),
		sigPath:    filepath.Join(dir, "bundle.yaml.sig"),
	}
}

func newUpdater(t *testing.T, e *env, fetcher bundleupd.Fetcher, opts ...func(*bundleupd.Options)) *bundleupd.Updater {
	t.Helper()
	o := bundleupd.Options{
		Fetcher:    fetcher,
		Interval:   time.Hour,
		Holder:     e.holder,
		BundlePath: e.bundlePath,
		SigPath:    e.sigPath,
		PubkeyPath: e.kit.pubkeyPath,
	}
	for _, f := range opts {
		f(&o)
	}
	u, err := bundleupd.New(o)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestTick_HappyPathPublishesRouter(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	body := bundleYAML("2026-05-13-001", 5)
	f := &stubFetcher{feed: []func() (*bundleupd.FetchResult, error){
		func() (*bundleupd.FetchResult, error) {
			return &bundleupd.FetchResult{
				Bundle: []byte(body), Signature: e.kit.sign([]byte(body)), ETag: `"v1"`,
			}, nil
		},
	}}
	u := newUpdater(t, e, f)
	if err := u.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	r := e.holder.Load()
	if r == nil || r.BundleVersion() != "2026-05-13-001" {
		t.Fatalf("router not published: %+v", r)
	}
	if _, err := os.Stat(e.bundlePath); err != nil {
		t.Errorf("bundle file not present: %v", err)
	}
	if _, err := os.Stat(e.sigPath); err != nil {
		t.Errorf("sig file not present: %v", err)
	}
}

func TestTick_NotModifiedIsNoOp(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	f := &stubFetcher{feed: []func() (*bundleupd.FetchResult, error){
		func() (*bundleupd.FetchResult, error) {
			return &bundleupd.FetchResult{NotModified: true}, nil
		},
	}}
	u := newUpdater(t, e, f)
	if err := u.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.holder.Load() != nil {
		t.Error("304 should not produce a router")
	}
	if _, err := os.Stat(e.bundlePath); !os.IsNotExist(err) {
		t.Error("304 should not write a bundle file")
	}
}

func TestTick_IdenticalHashSkipsLoad(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	body := bundleYAML("2026-05-13-001", 5)
	sig := e.kit.sign([]byte(body))
	f := &stubFetcher{feed: []func() (*bundleupd.FetchResult, error){
		func() (*bundleupd.FetchResult, error) {
			return &bundleupd.FetchResult{Bundle: []byte(body), Signature: sig, ETag: `"v1"`}, nil
		},
		func() (*bundleupd.FetchResult, error) {
			// Same content, no ETag.
			return &bundleupd.FetchResult{Bundle: []byte(body), Signature: sig, ETag: ""}, nil
		},
	}}
	u := newUpdater(t, e, f)
	if err := u.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	r1 := e.holder.Load()
	if err := u.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	r2 := e.holder.Load()
	if r1 != r2 {
		t.Error("identical-hash second tick swapped the router unnecessarily")
	}
}

func TestTick_BadSignatureKeepsCurrent(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	good := bundleYAML("2026-05-13-001", 5)
	bad := bundleYAML("2026-05-13-002", 5)
	f := &stubFetcher{feed: []func() (*bundleupd.FetchResult, error){
		func() (*bundleupd.FetchResult, error) {
			return &bundleupd.FetchResult{Bundle: []byte(good), Signature: e.kit.sign([]byte(good))}, nil
		},
		func() (*bundleupd.FetchResult, error) {
			// Sign with the wrong key.
			otherPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			return &bundleupd.FetchResult{Bundle: []byte(bad), Signature: signWith(otherPriv, []byte(bad))}, nil
		},
	}}
	u := newUpdater(t, e, f)
	if err := u.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	old := e.holder.Load()
	if old == nil {
		t.Fatal("first Tick did not publish")
	}
	if err := u.Tick(context.Background()); err == nil || !strings.Contains(err.Error(), "verify") {
		t.Errorf("expected verify failure, got %v", err)
	}
	if got := e.holder.Load(); got != old {
		t.Error("bad-signature Tick should have left router unchanged")
	}
	if _, err := os.Stat(e.bundlePath + ".staged"); !os.IsNotExist(err) {
		t.Errorf("staged file should have been cleaned up; got err=%v", err)
	}
}

func TestTick_DowngradeRefused(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	newer := bundleYAML("2026-05-13-002", 5)
	older := bundleYAML("2026-05-13-001", 5)
	f := &stubFetcher{feed: []func() (*bundleupd.FetchResult, error){
		func() (*bundleupd.FetchResult, error) {
			return &bundleupd.FetchResult{Bundle: []byte(newer), Signature: e.kit.sign([]byte(newer))}, nil
		},
		func() (*bundleupd.FetchResult, error) {
			return &bundleupd.FetchResult{Bundle: []byte(older), Signature: e.kit.sign([]byte(older))}, nil
		},
	}}
	u := newUpdater(t, e, f)
	if err := u.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := u.Tick(context.Background()); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Errorf("expected downgrade refusal, got %v", err)
	}
}

func TestTick_PromoteRotatesToPrevious(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v1 := bundleYAML("2026-05-13-001", 5)
	v2 := bundleYAML("2026-05-13-002", 5)
	f := &stubFetcher{feed: []func() (*bundleupd.FetchResult, error){
		func() (*bundleupd.FetchResult, error) {
			return &bundleupd.FetchResult{Bundle: []byte(v1), Signature: e.kit.sign([]byte(v1))}, nil
		},
		func() (*bundleupd.FetchResult, error) {
			return &bundleupd.FetchResult{Bundle: []byte(v2), Signature: e.kit.sign([]byte(v2))}, nil
		},
	}}
	u := newUpdater(t, e, f)
	if err := u.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := u.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	prevBundle := e.bundlePath + ".previous"
	if _, err := os.Stat(prevBundle); err != nil {
		t.Errorf("expected previous bundle to exist: %v", err)
	}
	got, _ := os.ReadFile(prevBundle)
	if !strings.Contains(string(got), "2026-05-13-001") {
		t.Errorf("previous bundle does not look like v1: %q", string(got))
	}
}

func TestTick_OnSwapCalled(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	body := bundleYAML("2026-05-13-001", 5)
	f := &stubFetcher{feed: []func() (*bundleupd.FetchResult, error){
		func() (*bundleupd.FetchResult, error) {
			return &bundleupd.FetchResult{Bundle: []byte(body), Signature: e.kit.sign([]byte(body))}, nil
		},
	}}
	var swapped atomic.Pointer[profile.Bundle]
	u := newUpdater(t, e, f, func(o *bundleupd.Options) {
		o.OnSwap = func(b *profile.Bundle) { swapped.Store(b) }
	})
	if err := u.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := swapped.Load(); got == nil || got.BundleVersion != "2026-05-13-001" {
		t.Errorf("OnSwap not called or with wrong bundle: %+v", got)
	}
}

func TestPoke_TriggersImmediateTickInRun(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	body := bundleYAML("2026-05-13-001", 5)
	f := &stubFetcher{feed: []func() (*bundleupd.FetchResult, error){
		func() (*bundleupd.FetchResult, error) {
			return &bundleupd.FetchResult{Bundle: []byte(body), Signature: e.kit.sign([]byte(body))}, nil
		},
	}}
	u := newUpdater(t, e, f, func(o *bundleupd.Options) { o.Interval = time.Hour })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- u.Run(ctx) }()

	u.Poke()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if e.holder.Load() != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e.holder.Load() == nil {
		t.Fatal("Poke did not trigger a Tick within 2s")
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run returned %v, want nil", err)
	}
}

func TestNew_RejectsBadOptions(t *testing.T) {
	t.Parallel()
	good := bundleupd.Options{
		Fetcher:    &stubFetcher{},
		Interval:   time.Hour,
		Holder:     profile.NewHolder(nil),
		BundlePath: "b", SigPath: "s", PubkeyPath: "p",
	}
	for name, mut := range map[string]func(bundleupd.Options) bundleupd.Options{
		"no fetcher":  func(o bundleupd.Options) bundleupd.Options { o.Fetcher = nil; return o },
		"no holder":   func(o bundleupd.Options) bundleupd.Options { o.Holder = nil; return o },
		"zero interval": func(o bundleupd.Options) bundleupd.Options { o.Interval = 0; return o },
		"no bundle path": func(o bundleupd.Options) bundleupd.Options { o.BundlePath = ""; return o },
	} {
		if _, err := bundleupd.New(mut(good)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestTick_FetcherError(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	f := &stubFetcher{feed: []func() (*bundleupd.FetchResult, error){
		func() (*bundleupd.FetchResult, error) { return nil, errors.New("network down") },
	}}
	u := newUpdater(t, e, f)
	err := u.Tick(context.Background())
	if err == nil || !strings.Contains(err.Error(), "network down") {
		t.Errorf("expected fetcher error surfaced, got %v", err)
	}
}

// --- HTTPFetcher tests ---

func TestHTTPFetcher_FetchOK(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		if strings.HasSuffix(r.URL.Path, ".sig") {
			_, _ = w.Write([]byte("sig"))
			return
		}
		_, _ = w.Write([]byte("bundle"))
	}))
	defer srv.Close()

	f := &bundleupd.HTTPFetcher{
		BundleURL: srv.URL + "/bundle.yaml",
		SigURL:    srv.URL + "/bundle.yaml.sig",
		Client:    srv.Client(),
	}
	res, err := f.Fetch(context.Background(), "")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.NotModified {
		t.Error("unexpected NotModified")
	}
	if string(res.Bundle) != "bundle" || string(res.Signature) != "sig" {
		t.Errorf("payload: %q / %q", res.Bundle, res.Signature)
	}
	if res.ETag != `"v1"` {
		t.Errorf("ETag = %q", res.ETag)
	}
}

func TestHTTPFetcher_NotModified(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte("bundle"))
	}))
	defer srv.Close()
	f := &bundleupd.HTTPFetcher{
		BundleURL: srv.URL + "/bundle.yaml",
		SigURL:    srv.URL + "/bundle.yaml.sig",
		Client:    srv.Client(),
	}
	res, err := f.Fetch(context.Background(), `"v1"`)
	if err != nil {
		t.Fatal(err)
	}
	if !res.NotModified {
		t.Error("expected NotModified on 304")
	}
}

func TestHTTPFetcher_Non200Errors(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	f := &bundleupd.HTTPFetcher{
		BundleURL: srv.URL + "/bundle.yaml",
		SigURL:    srv.URL + "/bundle.yaml.sig",
		Client:    srv.Client(),
	}
	if _, err := f.Fetch(context.Background(), ""); err == nil {
		t.Error("expected error on 500")
	}
}
