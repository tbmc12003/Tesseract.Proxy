package profile_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/equinomics/tesseract-proxy/internal/profile"
)

const goldenBundle = `schema_version: 1
bundle_version: 2026-05-13-001
issued_at: 2026-05-13T10:00:00Z
issuer: equinomics
min_proxy_version: 0.4.0

brokers:
  - id: kotakneo
    display_name: Kotak Neo
    host: gw-napi.kotaksecurities.com
    enabled: true
    order_endpoints:
      - method: POST
        path: /Orders/2.0/quick/order/rule/ms/place
        kind: place
      - method: POST
        path: /Orders/2.0/quick/order/vr/modify
        kind: modify
      - method: POST
        path: /Orders/2.0/quick/order/cancel
        kind: cancel
    idempotency:
      client_order_id_header: X-Client-Order-Id
      client_order_id_body_path: ""
      echo_in_response_path: data.orderNumber
    rate_limit:
      per_user_rps: 5
      per_user_burst: 10

  - id: fyers
    display_name: Fyers
    host: api-t1.fyers.in
    enabled: true
    order_endpoints:
      - method: POST
        path: /api/v3/orders/sync
        kind: place
      - method: PATCH
        path: /api/v3/orders/sync
        kind: modify
      - method: DELETE
        path: /api/v3/orders/sync
        kind: cancel
      - method: GET
        path: "/api/v3/orders/{order_id}"
        kind: cancel
    idempotency:
      client_order_id_header: ""
      client_order_id_body_path: $.orderTag
      echo_in_response_path: id
    rate_limit:
      per_user_rps: 5
      per_user_burst: 10

  - id: papertrader
    display_name: PaperTrader (Test)
    host: papertrader.local
    enabled: false
    order_endpoints:
      - method: POST
        path: /Orders/2.0/quick/order/rule/ms/place
        kind: place
    idempotency:
      client_order_id_header: X-Client-Order-Id
      client_order_id_body_path: ""
      echo_in_response_path: data.orderNumber
    rate_limit:
      per_user_rps: 100
      per_user_burst: 200
`

// testEnv writes a signed bundle to a temp directory and returns paths the
// loader needs. Each helper call produces an isolated, freshly-signed set —
// no shared global key state, no fixture files checked in.
type testEnv struct {
	dir            string
	bundlePath     string
	sigPath        string
	pubkeyPath     string
	privKey        *ecdsa.PrivateKey
	bundleContents []byte
}

func newTestEnv(t *testing.T, bundleYAML string) *testEnv {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	dir := t.TempDir()
	env := &testEnv{
		dir:            dir,
		bundlePath:     filepath.Join(dir, "bundle.yaml"),
		sigPath:        filepath.Join(dir, "bundle.yaml.sig"),
		pubkeyPath:     filepath.Join(dir, "pubkey.pem"),
		privKey:        priv,
		bundleContents: []byte(bundleYAML),
	}
	mustWrite(t, env.bundlePath, env.bundleContents)
	h := sha256.Sum256(env.bundleContents)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	mustWrite(t, env.sigPath, sig)
	mustWrite(t, env.pubkeyPath, encodePubkey(t, &priv.PublicKey))
	return env
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func encodePubkey(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func (e *testEnv) opts() profile.LoadOptions {
	return profile.LoadOptions{
		BundlePath: e.bundlePath,
		SigPath:    e.sigPath,
		PubkeyPath: e.pubkeyPath,
	}
}

func TestLoadAndVerify_Golden(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, goldenBundle)
	res, err := profile.LoadAndVerify(env.opts())
	if err != nil {
		t.Fatalf("LoadAndVerify: %v", err)
	}
	if got, want := res.Bundle.BundleVersion, "2026-05-13-001"; got != want {
		t.Errorf("BundleVersion = %q, want %q", got, want)
	}
	if got := len(res.Bundle.Brokers); got != 3 {
		t.Errorf("Brokers length = %d, want 3", got)
	}
	if res.Router.BundleVersion() != "2026-05-13-001" {
		t.Errorf("Router.BundleVersion mismatch")
	}
}

func TestLoadAndVerify_SignatureFailure(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, goldenBundle)
	// Tamper with the bundle on disk after signing.
	tampered := append([]byte{}, env.bundleContents...)
	tampered[0] = '#' // turn first line into a comment
	mustWrite(t, env.bundlePath, tampered)

	_, err := profile.LoadAndVerify(env.opts())
	if err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("expected signature failure, got %v", err)
	}
}

func TestLoadAndVerify_WrongPubkey(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, goldenBundle)
	// Overwrite the pubkey with a freshly-generated unrelated one.
	otherPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, env.pubkeyPath, encodePubkey(t, &otherPriv.PublicKey))

	_, err = profile.LoadAndVerify(env.opts())
	if err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("expected verification failure, got %v", err)
	}
}

func TestLoadAndVerify_SignatureWrongLength(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, goldenBundle)
	mustWrite(t, env.sigPath, []byte("short"))
	_, err := profile.LoadAndVerify(env.opts())
	if err == nil || !strings.Contains(err.Error(), "signature:") {
		t.Fatalf("expected signature-length failure, got %v", err)
	}
}

func TestLoadAndVerify_PubkeyNotPEM(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, goldenBundle)
	mustWrite(t, env.pubkeyPath, []byte("not a pem file"))
	_, err := profile.LoadAndVerify(env.opts())
	if err == nil || !strings.Contains(err.Error(), "PEM") {
		t.Fatalf("expected PEM error, got %v", err)
	}
}

func TestLoadAndVerify_DowngradeRefused(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, goldenBundle)
	opts := env.opts()
	opts.PreviousBundleVersion = "2026-05-13-999" // higher than the bundle
	_, err := profile.LoadAndVerify(opts)
	if err == nil || !strings.Contains(err.Error(), "downgrade refused") {
		t.Fatalf("expected downgrade refusal, got %v", err)
	}
}

func TestLoadAndVerify_DowngradeEqualRefused(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, goldenBundle)
	opts := env.opts()
	opts.PreviousBundleVersion = "2026-05-13-001" // equal to the bundle
	_, err := profile.LoadAndVerify(opts)
	if err == nil || !strings.Contains(err.Error(), "downgrade refused") {
		t.Fatalf("expected downgrade refusal on equal version, got %v", err)
	}
}

func TestLoadAndVerify_MonotonicAccept(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, goldenBundle)
	opts := env.opts()
	opts.PreviousBundleVersion = "2026-05-12-001" // strictly older
	if _, err := profile.LoadAndVerify(opts); err != nil {
		t.Fatalf("expected monotonic accept, got %v", err)
	}
}

func TestLoadAndVerify_MinProxyVersion(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, goldenBundle)
	opts := env.opts()
	opts.BinaryVersion = "0.3.9" // less than bundle's 0.4.0
	_, err := profile.LoadAndVerify(opts)
	if err == nil || !strings.Contains(err.Error(), "min_proxy_version") {
		t.Fatalf("expected min_proxy_version refusal, got %v", err)
	}
}

func TestLoadAndVerify_MinProxyVersion_DevBypass(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, goldenBundle)
	opts := env.opts()
	opts.BinaryVersion = "dev"
	if _, err := profile.LoadAndVerify(opts); err != nil {
		t.Fatalf("dev should bypass min_proxy_version: %v", err)
	}
}

func TestLoadAndVerify_MinProxyVersion_Accept(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, goldenBundle)
	opts := env.opts()
	opts.BinaryVersion = "v0.4.0"
	if _, err := profile.LoadAndVerify(opts); err != nil {
		t.Fatalf("matching version should accept: %v", err)
	}
}

func TestLoadAndVerify_SchemaRejections(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		mut  func(string) string
		want string
	}{
		{
			name: "unknown top-level field",
			mut:  func(b string) string { return b + "\nstray_field: 1\n" },
			want: "stray_field",
		},
		{
			name: "wrong schema_version",
			mut:  func(b string) string { return strings.Replace(b, "schema_version: 1", "schema_version: 99", 1) },
			want: "schema_version",
		},
		{
			name: "missing bundle_version",
			mut:  func(b string) string { return strings.Replace(b, "bundle_version: 2026-05-13-001", `bundle_version: ""`, 1) },
			want: "bundle_version",
		},
		{
			name: "invalid min_proxy_version",
			mut:  func(b string) string { return strings.Replace(b, "min_proxy_version: 0.4.0", "min_proxy_version: not-semver", 1) },
			want: "min_proxy_version",
		},
		{
			name: "host with wildcard",
			mut:  func(b string) string { return strings.Replace(b, "host: gw-napi.kotaksecurities.com", "host: '*.kotaksecurities.com'", 1) },
			want: "wildcards not allowed",
		},
		{
			name: "host is raw ip",
			mut:  func(b string) string { return strings.Replace(b, "host: gw-napi.kotaksecurities.com", "host: 1.2.3.4", 1) },
			want: "raw IP not allowed",
		},
		{
			name: "host is single label",
			mut:  func(b string) string { return strings.Replace(b, "host: gw-napi.kotaksecurities.com", "host: localhost", 1) },
			want: "dotted hostname",
		},
		{
			name: "unknown method",
			mut: func(b string) string {
				return strings.Replace(b, "method: POST\n        path: /Orders/2.0/quick/order/rule/ms/place",
					"method: TRACE\n        path: /Orders/2.0/quick/order/rule/ms/place", 1)
			},
			want: "method",
		},
		{
			name: "unknown kind",
			mut: func(b string) string {
				return strings.Replace(b,
					"path: /Orders/2.0/quick/order/rule/ms/place\n        kind: place",
					"path: /Orders/2.0/quick/order/rule/ms/place\n        kind: nuke", 1)
			},
			want: "kind",
		},
		{
			name: "path with regex special",
			mut: func(b string) string {
				return strings.Replace(b, "/Orders/2.0/quick/order/rule/ms/place", `"/Orders/2.0/.*/order/rule/ms/place"`, 1)
			},
			want: "invalid character",
		},
		{
			name: "path without leading slash",
			mut: func(b string) string {
				return strings.Replace(b, "/Orders/2.0/quick/order/rule/ms/place", "Orders/2.0/quick/order/rule/ms/place", 1)
			},
			want: "must start with /",
		},
		{
			name: "unclosed placeholder",
			mut: func(b string) string {
				return strings.Replace(b, `"/api/v3/orders/{order_id}"`, `"/api/v3/orders/{order_id"`, 1)
			},
			want: "unclosed",
		},
		{
			name: "empty brokers",
			mut: func(b string) string {
				idx := strings.Index(b, "brokers:")
				return b[:idx] + "brokers: []\n"
			},
			want: "at least one broker",
		},
		{
			name: "duplicate broker id",
			mut: func(b string) string {
				// turn the fyers entry into a second kotakneo
				return strings.Replace(b, "id: fyers", "id: kotakneo", 1)
			},
			want: "duplicate id",
		},
		{
			name: "invalid broker id",
			mut: func(b string) string {
				return strings.Replace(b, "id: kotakneo", "id: Kotak-Neo", 1)
			},
			want: "id",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env := newTestEnv(t, tc.mut(goldenBundle))
			_, err := profile.LoadAndVerify(env.opts())
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestRouter_Lookup(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, goldenBundle)
	res, err := profile.LoadAndVerify(env.opts())
	if err != nil {
		t.Fatal(err)
	}
	r := res.Router

	// Exact-path match.
	if m := r.Lookup("kotakneo", "POST", "/Orders/2.0/quick/order/cancel"); m == nil || m.Endpoint.Kind != profile.KindCancel {
		t.Errorf("kotakneo cancel: got %+v", m)
	}
	// Placeholder match.
	if m := r.Lookup("fyers", "GET", "/api/v3/orders/abc123"); m == nil {
		t.Errorf("fyers placeholder: no match")
	}
	// Placeholder does not match across slashes.
	if m := r.Lookup("fyers", "GET", "/api/v3/orders/abc/extra"); m != nil {
		t.Errorf("placeholder leaked across slash: %+v", m)
	}
	// Wrong method.
	if m := r.Lookup("kotakneo", "GET", "/Orders/2.0/quick/order/cancel"); m != nil {
		t.Errorf("wrong-method match leaked: %+v", m)
	}
	// Unknown broker.
	if m := r.Lookup("nobroker", "POST", "/Orders/2.0/quick/order/cancel"); m != nil {
		t.Errorf("unknown-broker match leaked: %+v", m)
	}
	// Disabled broker (papertrader.enabled = false).
	if m := r.Lookup("papertrader", "POST", "/Orders/2.0/quick/order/rule/ms/place"); m != nil {
		t.Errorf("disabled broker matched: %+v", m)
	}
	// Path mismatch.
	if m := r.Lookup("kotakneo", "POST", "/Orders/2.0/quick/order/foo"); m != nil {
		t.Errorf("unknown-path match leaked: %+v", m)
	}
}
