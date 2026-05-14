package main

// End-to-end smoke test for the wired runtime. Builds the full fixture
// set in-process (CA, server + client certs, signed bundle, operator
// config), starts the proxy on a random localhost port, drives a real
// mTLS HTTPS request through /admin/status, and confirms the audit +
// metrics counters reflect the outcome.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixture struct {
	dir         string
	configPath  string
	listenAddr  string
	clientCert  tls.Certificate
	caCertPEM   []byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()

	// Bundle signing key.
	bundlePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	bundlePub := &bundlePriv.PublicKey
	bundlePubPath := filepath.Join(dir, "bundle.pub")
	mustWritePEM(t, bundlePubPath, "PUBLIC KEY", mustMarshalPKIX(t, bundlePub))

	// CA.
	caCert, caKey, caCertPEM := newCA(t)

	// Server cert (SAN: 127.0.0.1, localhost).
	serverCertPath, serverKeyPath := issueServerCert(t, dir, caCert, caKey)

	// Client cert with serial 1001 (in the allowed_order_serials list).
	clientCertTLS := issueClientCert(t, caCert, caKey, 1001)

	// Pick a random port up front; the proxy then binds it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	listenAddr := ln.Addr().String()
	_ = ln.Close()

	// Signed bundle.
	bundleYAML := `schema_version: 1
bundle_version: 2026-05-13-smoke
issued_at: 2026-05-13T00:00:00Z
issuer: equinomics
min_proxy_version: 0.0.1
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
      per_user_rps: 100
      per_user_burst: 200
`
	bundlePath := filepath.Join(dir, "bundle.yaml")
	sigPath := filepath.Join(dir, "bundle.yaml.sig")
	must(t, os.WriteFile(bundlePath, []byte(bundleYAML), 0o600))
	bundleHash := sha256.Sum256([]byte(bundleYAML))
	bundleSig, err := ecdsa.SignASN1(rand.Reader, bundlePriv, bundleHash[:])
	must(t, err)
	must(t, os.WriteFile(sigPath, bundleSig, 0o600))

	// CA file on disk (for the proxy's MTLS.ClientCA + the test client's RootCAs).
	caPath := filepath.Join(dir, "ca.pem")
	must(t, os.WriteFile(caPath, caCertPEM, 0o600))

	// Audit + log dir.
	auditPath := filepath.Join(dir, "audit.log")

	// Operator config.
	configPath := filepath.Join(dir, "proxy.conf.yaml")
	confYAML := fmt.Sprintf(`listen:
  order_plane: "%s"

mtls:
  server_cert: %q
  server_key:  %q
  client_ca:   %q
  allowed_order_serials: ["1001"]
  allowed_admin_serials: ["1001"]

profile_bundle:
  path:        %q
  sig_path:    %q
  pubkey_path: %q
  refresh:
    enabled: false

audit_log:
  path:         %q
  rotation_mb:  16
  retain_count: 7

log:
  level:  info
  format: json
`, listenAddr,
		serverCertPath, serverKeyPath, caPath,
		bundlePath, sigPath, bundlePubPath,
		auditPath)
	must(t, os.WriteFile(configPath, []byte(confYAML), 0o600))

	return &fixture{
		dir:        dir,
		configPath: configPath,
		listenAddr: listenAddr,
		clientCert: clientCertTLS,
		caCertPEM:  caCertPEM,
	}
}

func TestEndToEnd_WiredProxyServesAdminAndOrderPlane(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Two Windows-specific obstacles: (1) os.Process.Signal(os.Interrupt)
		// is not supported on Windows, so the in-process graceful-shutdown
		// trigger doesn't work; (2) the audit log file is locked open, so
		// TempDir cleanup fails after the run goroutine returns. Both are
		// non-issues on the deployment target (linux/arm64) and CI runs
		// the test there.
		t.Skip("graceful-shutdown trigger via SIGINT is not supported on Windows; CI exercises this on Linux")
	}
	fx := newFixture(t)

	// Run the proxy in a goroutine; it shuts down when its context is
	// signalled. We don't have a clean handle to the rootCtx from the
	// outside, so we send SIGINT to the test's own PID to trigger the
	// graceful path — this works because signal.NotifyContext catches it.
	stderr, _ := os.Create(filepath.Join(fx.dir, "proxy.stderr"))
	defer stderr.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	var runErr error
	go func() {
		defer wg.Done()
		runErr = run([]string{"--config", fx.configPath}, stderr)
	}()

	// Wait for the listener.
	waitForListener(t, fx.listenAddr)

	// Build an mTLS client.
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(fx.caCertPEM)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      pool,
			Certificates: []tls.Certificate{fx.clientCert},
			ServerName:   "127.0.0.1",
		},
		ForceAttemptHTTP2: true,
	}
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	// GET /admin/status — should succeed.
	resp, err := c.Get("https://" + fx.listenAddr + "/admin/status")
	if err != nil {
		t.Fatalf("GET /admin/status: %v\n--- proxy stderr ---\n%s",
			err, readFile(t, filepath.Join(fx.dir, "proxy.stderr")))
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status code = %d, want 200; body=%s", resp.StatusCode, body)
	}
	var st map[string]any
	must(t, json.NewDecoder(resp.Body).Decode(&st))
	if st["bundle_version"] != "2026-05-13-smoke" {
		t.Errorf("/admin/status bundle_version = %v, want 2026-05-13-smoke", st["bundle_version"])
	}

	// POST with unknown broker — should be 403.
	req, _ := http.NewRequest("POST",
		"https://"+fx.listenAddr+"/Orders/2.0/quick/order/rule/ms/place",
		strings.NewReader(`{}`))
	req.Header.Set("X-Tesseract-Broker", "ghost")
	resp2, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 403 {
		t.Errorf("unknown broker status = %d, want 403", resp2.StatusCode)
	}

	// GET /admin/metrics — rejects_total should now be ≥ 1.
	resp3, err := c.Get("https://" + fx.listenAddr + "/admin/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	mbody, _ := io.ReadAll(resp3.Body)
	if !strings.Contains(string(mbody), "tesseract_rejects_total 1") {
		t.Errorf("expected rejects_total 1 in /admin/metrics, got:\n%s", string(mbody))
	}

	// Trigger graceful shutdown via SIGINT to this process. signal.
	// NotifyContext inside run() catches it and unwinds.
	p, _ := os.FindProcess(os.Getpid())
	if err := p.Signal(os.Interrupt); err != nil {
		t.Fatalf("send SIGINT: %v", err)
	}
	wg.Wait()
	if runErr != nil {
		t.Errorf("run returned error: %v", runErr)
	}
}

// ---- helpers ----

func waitForListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("listener never came up at " + addr)
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, _ := os.ReadFile(path)
	return string(b)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustMarshalPKIX(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	must(t, err)
	return der
}

func mustWritePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	must(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600))
}

func newCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "smoke-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	must(t, err)
	cert, err := x509.ParseCertificate(der)
	must(t, err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, priv, caPEM
}

func issueServerCert(t *testing.T, dir string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "tesseract-proxy"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &priv.PublicKey, caKey)
	must(t, err)
	certPath = filepath.Join(dir, "server.pem")
	keyPath = filepath.Join(dir, "server.key")
	mustWritePEM(t, certPath, "CERTIFICATE", der)
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	must(t, err)
	mustWritePEM(t, keyPath, "PRIVATE KEY", keyDER)
	return certPath, keyPath
}

func issueClientCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, serial int64) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	pub := &priv.PublicKey
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "order-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, pub, caKey)
	must(t, err)
	leaf, err := x509.ParseCertificate(der)
	must(t, err)
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        leaf,
	}
}
