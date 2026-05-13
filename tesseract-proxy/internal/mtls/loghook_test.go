package mtls_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/equinomics/tesseract-proxy/internal/metrics"
	"github.com/equinomics/tesseract-proxy/internal/mtls"
)

func TestClassifyHandshakeError(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		line string
		want string
	}{
		{"http: TLS handshake error from 1.2.3.4:5: mtls: client serial 9999 not in allowlist", "unknown_serial"},
		{"http: TLS handshake error from x: tls: client didn't provide a certificate", "no_client_cert"},
		{"http: TLS handshake error from x: tls: failed to verify certificate: x509: unknown certificate authority", "wrong_ca"},
		{"http: TLS handshake error from x: tls: certificate has expired or is not yet valid", "expired"},
		{"http: TLS handshake error from x: tls: client offered only unsupported versions: [303]", "tls_version"},
		{"http: TLS handshake error from x: weird unexpected thing", "other"},
	} {
		if got := mtls.ClassifyHandshakeError(tc.line); got != tc.want {
			t.Errorf("classify(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}
}

func TestHandshakeErrorLogger_IncrementsCounterAndForwards(t *testing.T) {
	t.Parallel()
	var counter metrics.LabeledCounter
	var fallback bytes.Buffer
	lg := mtls.HandshakeErrorLogger(&counter, &fallback)

	lg.Print("http: TLS handshake error from 10.0.0.1: mtls: client serial 9999 not in allowlist")
	lg.Print("http: TLS handshake error from 10.0.0.2: tls: client didn't provide a certificate")
	lg.Print("an unrelated stdlib log line")

	snap := counter.Snapshot()
	if snap["unknown_serial"] != 1 || snap["no_client_cert"] != 1 {
		t.Errorf("counter snapshot = %+v", snap)
	}
	if !strings.Contains(fallback.String(), "unrelated stdlib log line") {
		t.Errorf("fallback writer did not receive all lines: %q", fallback.String())
	}
}

// TestHandshakeLogger_EndToEnd wires an http.Server with our mtls config
// + the loghook ErrorLog, and confirms an unauth'd connection bumps the
// handshake-failure counter.
func TestHandshakeLogger_EndToEnd(t *testing.T) {
	t.Parallel()
	kit := newCertKit(t)
	certPath, keyPath := kit.issueServerCert(t, 100)
	caPath := kit.writeCAFile(t)
	cfg, _, err := mtls.BuildServerConfig(mtls.Options{
		ServerCertPath:      certPath,
		ServerKeyPath:       keyPath,
		ClientCAPath:        caPath,
		AllowedOrderSerials: []string{"1001"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var counter metrics.LabeledCounter
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:   http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		TLSConfig: cfg,
		ErrorLog:  mtls.HandshakeErrorLogger(&counter, io.Discard),
	}
	go func() { _ = srv.ServeTLS(listener, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	// Client with no client cert at all → handshake will fail; the
	// server-side ErrorLog gets a "TLS handshake error" line that the
	// loghook classifies and counts.
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(kit.caCertPEM)
	tr := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    pool,
		ServerName: "127.0.0.1",
	}}
	c := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	_, _ = c.Get("https://" + listener.Addr().String())

	// Allow up to 2s for the server-side ErrorLog write to land. The
	// handshake is synchronous from the client perspective but the log
	// emit may trail.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if labelSum(counter.Snapshot()) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if total := labelSum(counter.Snapshot()); total == 0 {
		t.Errorf("expected at least one handshake-failure counter bump, got %+v", counter.Snapshot())
	}
}

func labelSum(m map[string]int64) int64 {
	var s int64
	for _, v := range m {
		s += v
	}
	return s
}
