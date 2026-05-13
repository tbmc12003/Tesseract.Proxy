package mtls_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/equinomics/tesseract-proxy/internal/mtls"
)

// certKit owns a CA and produces server / client certs signed by it.
type certKit struct {
	caCert     *x509.Certificate
	caKey      ed25519.PrivateKey
	caCertPEM  []byte
	otherCAKey ed25519.PrivateKey  // a second, unrelated CA — for "valid cert from wrong CA" tests
	otherCA    *x509.Certificate
}

func newCertKit(t *testing.T) *certKit {
	t.Helper()
	caCert, caKey, caPEM := newCA(t, "Tesseract Test CA")
	otherCert, otherKey, _ := newCA(t, "Other CA")
	return &certKit{
		caCert: caCert, caKey: caKey, caCertPEM: caPEM,
		otherCA: otherCert, otherCAKey: otherKey,
	}
}

func newCA(t *testing.T, cn string) (*x509.Certificate, ed25519.PrivateKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, priv, pemBytes
}

// issueServerCert produces a server cert valid for 127.0.0.1.
func (k *certKit) issueServerCert(t *testing.T, serial int64) (certPEMPath, keyPEMPath string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "tesseract-proxy"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, k.caCert, pub, k.caKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPEMPath = filepath.Join(dir, "server.pem")
	keyPEMPath = filepath.Join(dir, "server.key")
	writePEM(t, certPEMPath, "CERTIFICATE", der)
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, keyPEMPath, "PRIVATE KEY", keyDER)
	return certPEMPath, keyPEMPath
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (k *certKit) writeCAFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, k.caCertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// issueClientCert mints a client cert with the given serial, signed by
// `signer` (one of caKey or otherCAKey).
func (k *certKit) issueClientCert(t *testing.T, serial int64, cn string, signWith ed25519.PrivateKey, parent *x509.Certificate, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signWith)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        leaf,
	}
}

// buildServer wires the mTLS config into a small httptest server that
// returns the authenticated role.
func buildServer(t *testing.T, opts mtls.Options) (*httptest.Server, *mtls.Allowlist) {
	t.Helper()
	cfg, allowlist, err := mtls.BuildServerConfig(opts)
	if err != nil {
		t.Fatalf("BuildServerConfig: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := mtls.PeerRole(allowlist, r.TLS)
		_, _ = io.WriteString(w, role.String())
	}))
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, allowlist
}

// clientFor builds an HTTPS client that presents the given client cert and
// trusts our CA for the server.
func clientFor(t *testing.T, kit *certKit, clientCerts ...tls.Certificate) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(kit.caCertPEM)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			RootCAs:      pool,
			Certificates: clientCerts,
			NextProtos:   []string{"h2"},
			ServerName:   "127.0.0.1",
		},
		ForceAttemptHTTP2: true,
	}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

// stdSetup builds a server allowing order serial 1001 and admin serial
// 2001, and returns the kit + URL.
func stdSetup(t *testing.T) (*certKit, *httptest.Server) {
	kit := newCertKit(t)
	certPath, keyPath := kit.issueServerCert(t, 100)
	caPath := kit.writeCAFile(t)
	srv, _ := buildServer(t, mtls.Options{
		ServerCertPath:      certPath,
		ServerKeyPath:       keyPath,
		ClientCAPath:        caPath,
		AllowedOrderSerials: []string{"1001"},
		AllowedAdminSerials: []string{"2001"},
	})
	return kit, srv
}

func farFuture() time.Time   { return time.Now().Add(time.Hour) }
func farPast() time.Time     { return time.Now().Add(-2 * time.Hour) }
func oneHourAgo() time.Time  { return time.Now().Add(-time.Hour) }
func longAgo() time.Time     { return time.Now().Add(-48 * time.Hour) }

func TestHandshake_ValidOrderCert(t *testing.T) {
	t.Parallel()
	kit, srv := stdSetup(t)
	clientCert := kit.issueClientCert(t, 1001, "order-client", kit.caKey, kit.caCert, oneHourAgo(), farFuture())
	resp, err := clientFor(t, kit, clientCert).Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if got := string(body); got != "order" {
		t.Errorf("role = %q, want order", got)
	}
}

func TestHandshake_ValidAdminCert(t *testing.T) {
	t.Parallel()
	kit, srv := stdSetup(t)
	clientCert := kit.issueClientCert(t, 2001, "admin-client", kit.caKey, kit.caCert, oneHourAgo(), farFuture())
	resp, err := clientFor(t, kit, clientCert).Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if got := string(body); got != "admin" {
		t.Errorf("role = %q, want admin", got)
	}
}

func TestHandshake_NoClientCert(t *testing.T) {
	t.Parallel()
	kit, srv := stdSetup(t)
	_, err := clientFor(t, kit).Get(srv.URL) // no client certs
	if err == nil {
		t.Fatal("expected handshake error with no client cert, got nil")
	}
	// We don't pin on a specific error string — http2 reports it as "client
	// conn could not be established"; http1.1 reports the underlying TLS
	// error directly. Either way, the request failed at handshake, which is
	// the property we care about.
}

func TestHandshake_WrongCA(t *testing.T) {
	t.Parallel()
	kit, srv := stdSetup(t)
	// Sign the client cert with the OTHER CA, but its CN/serial would be valid.
	clientCert := kit.issueClientCert(t, 1001, "order-client", kit.otherCAKey, kit.otherCA, oneHourAgo(), farFuture())
	_, err := clientFor(t, kit, clientCert).Get(srv.URL)
	if err == nil {
		t.Fatal("expected handshake error from wrong-CA client cert")
	}
}

func TestHandshake_UnknownSerial(t *testing.T) {
	t.Parallel()
	kit, srv := stdSetup(t)
	clientCert := kit.issueClientCert(t, 9999, "stranger", kit.caKey, kit.caCert, oneHourAgo(), farFuture())
	_, err := clientFor(t, kit, clientCert).Get(srv.URL)
	if err == nil {
		t.Fatal("expected serial-allowlist rejection")
	}
}

func TestHandshake_ExpiredCert(t *testing.T) {
	t.Parallel()
	kit, srv := stdSetup(t)
	clientCert := kit.issueClientCert(t, 1001, "order-client", kit.caKey, kit.caCert, longAgo(), farPast())
	_, err := clientFor(t, kit, clientCert).Get(srv.URL)
	if err == nil {
		t.Fatal("expected handshake error from expired client cert")
	}
}

// "Revoked serial" semantics in this layer = removed from the allowlist
// via Replace; once removed, the next handshake from that serial is
// rejected exactly like an unknown serial.
func TestHandshake_RevokedSerial(t *testing.T) {
	t.Parallel()
	kit := newCertKit(t)
	certPath, keyPath := kit.issueServerCert(t, 100)
	caPath := kit.writeCAFile(t)
	_, allowlist := buildServer(t, mtls.Options{
		ServerCertPath:      certPath,
		ServerKeyPath:       keyPath,
		ClientCAPath:        caPath,
		AllowedOrderSerials: []string{"1001"},
		AllowedAdminSerials: []string{"2001"},
	})
	if err := allowlist.Replace(nil, []string{"2001"}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	// Now serial 1001 is no longer allow-listed.
	if got := allowlist.Classify(big.NewInt(1001)); got != mtls.RoleNone {
		t.Errorf("revoked serial classified as %v, want none", got)
	}
}

func TestHandshake_TLS12Rejected(t *testing.T) {
	t.Parallel()
	kit, srv := stdSetup(t)
	clientCert := kit.issueClientCert(t, 1001, "order-client", kit.caKey, kit.caCert, oneHourAgo(), farFuture())
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(kit.caCertPEM)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12, // force-downgrade attempt
			RootCAs:      pool,
			Certificates: []tls.Certificate{clientCert},
			ServerName:   "127.0.0.1",
		},
	}
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	_, err := c.Get(srv.URL)
	if err == nil {
		t.Fatal("expected TLS 1.2 to be rejected by TLS 1.3-only server")
	}
}

func TestBuildServerConfig_NoAllowedSerials(t *testing.T) {
	t.Parallel()
	kit := newCertKit(t)
	certPath, keyPath := kit.issueServerCert(t, 100)
	caPath := kit.writeCAFile(t)
	_, _, err := mtls.BuildServerConfig(mtls.Options{
		ServerCertPath: certPath,
		ServerKeyPath:  keyPath,
		ClientCAPath:   caPath,
	})
	if err == nil || !strings.Contains(err.Error(), "at least one allowed serial") {
		t.Fatalf("expected refusal when no serials provided, got %v", err)
	}
}

func TestBuildServerConfig_InvalidSerial(t *testing.T) {
	t.Parallel()
	kit := newCertKit(t)
	certPath, keyPath := kit.issueServerCert(t, 100)
	caPath := kit.writeCAFile(t)
	_, _, err := mtls.BuildServerConfig(mtls.Options{
		ServerCertPath:      certPath,
		ServerKeyPath:       keyPath,
		ClientCAPath:        caPath,
		AllowedOrderSerials: []string{"not-a-number"},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid serial") {
		t.Fatalf("expected invalid serial error, got %v", err)
	}
}

func TestBuildServerConfig_MissingCA(t *testing.T) {
	t.Parallel()
	kit := newCertKit(t)
	certPath, keyPath := kit.issueServerCert(t, 100)
	_, _, err := mtls.BuildServerConfig(mtls.Options{
		ServerCertPath:      certPath,
		ServerKeyPath:       keyPath,
		ClientCAPath:        filepath.Join(t.TempDir(), "missing-ca.pem"),
		AllowedOrderSerials: []string{"1001"},
	})
	if err == nil || !strings.Contains(err.Error(), "read client CA") {
		t.Fatalf("expected CA-read error, got %v", err)
	}
}

func TestRoleAllows(t *testing.T) {
	t.Parallel()
	if !mtls.RoleAdmin.Allows(mtls.RoleAdmin) {
		t.Error("admin should allow admin")
	}
	if !mtls.RoleAdmin.Allows(mtls.RoleOrder) {
		t.Error("admin should allow order")
	}
	if mtls.RoleOrder.Allows(mtls.RoleAdmin) {
		t.Error("order should not allow admin")
	}
	if mtls.RoleNone.Allows(mtls.RoleOrder) {
		t.Error("none should not allow order")
	}
}

func TestAllowlist_ClassifyNilSerial(t *testing.T) {
	t.Parallel()
	a, err := mtls.NewAllowlist(mtls.Options{
		AllowedOrderSerials: []string{"1001"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := a.Classify(nil); got != mtls.RoleNone {
		t.Errorf("nil serial = %v, want none", got)
	}
}
