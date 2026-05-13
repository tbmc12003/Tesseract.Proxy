package mtls

import (
	"io"
	"log"
	"strings"

	"github.com/equinomics/tesseract-proxy/internal/metrics"
)

// HandshakeErrorLogger returns a *log.Logger suitable for use as
// http.Server.ErrorLog. It inspects each write for the "TLS handshake
// error" pattern Go's TLS layer emits and increments the supplied
// labeled counter with a coarse reason classification before forwarding
// the line to fallback (typically the slog-routed writer).
//
// This is the integration point for the P2.16 mtls_handshake_failures
// counter: low-level TLS failures (wrong CA, expired client cert, TLS
// 1.2 attempt, missing cert) happen before VerifyConnection runs and are
// only visible through ErrorLog. Application-level rejections (serial
// not in allowlist) flow through OnHandshakeFailure on the tls.Config
// instead — see BuildServerConfig.
func HandshakeErrorLogger(c *metrics.LabeledCounter, fallback io.Writer) *log.Logger {
	return log.New(&handshakeWriter{c: c, fallback: fallback}, "", 0)
}

type handshakeWriter struct {
	c        *metrics.LabeledCounter
	fallback io.Writer
}

func (w *handshakeWriter) Write(p []byte) (int, error) {
	line := string(p)
	if strings.Contains(line, "TLS handshake error") {
		if w.c != nil {
			w.c.Inc(ClassifyHandshakeError(line))
		}
	}
	if w.fallback != nil {
		_, _ = w.fallback.Write(p)
	}
	return len(p), nil
}

// ClassifyHandshakeError maps a Go-emitted TLS handshake error line to a
// coarse reason label. Unknown patterns map to "other".
//
// Substring matching, not regex, on the stable parts of Go's stdlib
// error messages. If Go ever changes these strings the test suite
// catches it via TestClassifyHandshakeError.
func ClassifyHandshakeError(line string) string {
	switch {
	case strings.Contains(line, "not in allowlist"):
		return "unknown_serial"
	case strings.Contains(line, "didn't provide a certificate"),
		strings.Contains(line, "no client certificate"):
		return "no_client_cert"
	case strings.Contains(line, "unknown certificate authority"),
		strings.Contains(line, "verify certificate"):
		return "wrong_ca"
	case strings.Contains(line, "certificate has expired"),
		strings.Contains(line, "expired"):
		return "expired"
	case strings.Contains(line, "unsupported versions"),
		strings.Contains(line, "no supported versions"),
		strings.Contains(line, "protocol version"):
		return "tls_version"
	default:
		return "other"
	}
}
