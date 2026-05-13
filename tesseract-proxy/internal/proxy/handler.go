// Package proxy is the order-plane pass-through handler.
//
// Request flow:
//
//  1. X-Tesseract-Broker header → broker ID. Missing ⇒ 400.
//  2. Holder.Load().Lookup(brokerID, method, path) → match. Miss ⇒ 403.
//  3. Build outbound request, strip hop-by-hop + internal headers.
//  4. RoundTrip via the shared Transport.
//  5. Stream the response body straight back to the client.
//
// What this handler explicitly does NOT do (deliberately removed —
// stakeholder, 2026-05-13):
//   - Idempotency cache. Duplicate-suppression belongs in Tesseract,
//     which already owns retry policy and idempotency key generation.
//   - Rate limiting. Single-user scope: the user IS the only client.
//     If they overshoot, the broker will 429 them and they'll adjust.
//   - Response body buffering. Streaming saves a copy and a memory
//     allocation per order.
//
// What it still does (and why):
//   - mTLS gate (cert + serial allowlist) — defends the Lightsail IP
//     against internet scanners. Without it any stranger who finds the
//     public IP can submit orders.
//   - Allowlist check against the signed bundle — defends against a
//     compromised client-side bug attempting to forward to a non-broker
//     destination.
//   - Audit log emit — explicitly required.
//   - Panic recovery — keeps the listener up if anything below it
//     blows.
package proxy

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/equinomics/tesseract-proxy/internal/audit"
	"github.com/equinomics/tesseract-proxy/internal/metrics"
	"github.com/equinomics/tesseract-proxy/internal/profile"
)

const (
	HeaderBroker         = "X-Tesseract-Broker"
	HeaderIdempotencyKey = "X-Tesseract-Idempotency-Key" // forwarded upstream if present; not interpreted here
)

// Options configures a Handler.
type Options struct {
	// Holder owns the live Router. Hot path reads it lock-free per request.
	Holder *profile.Holder

	// Transport is the shared per-host connection pool used to talk to
	// brokers. One Transport for all brokers — Go's stdlib multiplexes
	// idle connections per (scheme, host), satisfying the "persistent
	// HTTP/2 per broker host" property without a per-broker Transport.
	Transport http.RoundTripper

	// Audit, if non-nil, receives one Record per request.
	Audit *audit.Writer

	// Metrics, if non-nil, is incremented with the request outcome.
	Metrics *metrics.Counters

	// BackendURL maps a broker profile to the outbound base URL.
	// Default: https://<broker.Host>. Tests override.
	BackendURL func(*profile.BrokerProfile) *url.URL

	Logger *slog.Logger
}

// Handler is the order-plane HTTP handler. /admin/* lives elsewhere.
type Handler struct {
	opts Options
}

// New constructs a Handler.
func New(opts Options) (*Handler, error) {
	if opts.Holder == nil {
		return nil, errors.New("proxy: Holder is required")
	}
	if opts.Transport == nil {
		return nil, errors.New("proxy: Transport is required")
	}
	if opts.BackendURL == nil {
		opts.BackendURL = defaultBackendURL
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Handler{opts: opts}, nil
}

func defaultBackendURL(b *profile.BrokerProfile) *url.URL {
	return &url.URL{Scheme: "https", Host: b.Host}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := audit.Record{
		Method:         r.Method,
		Path:           r.URL.Path,
		Serial:         peerSerial(r),
		IdempotencyKey: r.Header.Get(HeaderIdempotencyKey),
	}
	defer func() {
		rec.LatencyMs = time.Since(start).Milliseconds()
		if h.opts.Audit != nil {
			_ = h.opts.Audit.Log(rec)
		}
		if h.opts.Metrics != nil {
			h.opts.Metrics.IncOutcome(rec.Outcome)
		}
	}()
	defer func() {
		if p := recover(); p != nil {
			rec.Outcome = audit.OutcomeUpstreamErr
			rec.Status = http.StatusInternalServerError
			rec.Reason = fmt.Sprintf("panic: %v", p)
			h.opts.Logger.Error("proxy panic recovered",
				"panic", fmt.Sprintf("%v", p),
				"method", r.Method, "path", r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(w, `{"error":"internal server error"}`+"\n")
		}
	}()

	brokerID := r.Header.Get(HeaderBroker)
	if brokerID == "" {
		rec.Outcome, rec.Status, rec.Reason =
			audit.OutcomeReject, http.StatusBadRequest, "missing "+HeaderBroker+" header"
		h.fail(w, r, rec.Status, rec.Reason, nil)
		return
	}
	rec.BrokerID = brokerID

	router := h.opts.Holder.Load()
	if router == nil {
		rec.Outcome, rec.Status, rec.Reason =
			audit.OutcomeReject, http.StatusServiceUnavailable, "no bundle loaded"
		h.fail(w, r, rec.Status, rec.Reason, nil)
		return
	}
	rec.BundleVersion = router.BundleVersion()

	match := router.Lookup(brokerID, r.Method, r.URL.Path)
	if match == nil {
		rec.Outcome, rec.Status, rec.Reason =
			audit.OutcomeReject, http.StatusForbidden, "request does not match an allowlist entry"
		h.fail(w, r, rec.Status, rec.Reason,
			[]any{"broker", brokerID, "method", r.Method, "path", r.URL.Path})
		return
	}

	out, err := h.buildOutbound(r, match.Broker)
	if err != nil {
		rec.Outcome, rec.Status, rec.Reason =
			audit.OutcomeUpstreamErr, http.StatusInternalServerError, "build outbound: "+err.Error()
		h.fail(w, r, rec.Status, rec.Reason, nil)
		return
	}

	resp, err := h.opts.Transport.RoundTrip(out)
	if err != nil {
		rec.Outcome, rec.Status, rec.Reason =
			audit.OutcomeUpstreamErr, http.StatusBadGateway, "upstream: "+err.Error()
		h.fail(w, r, rec.Status, rec.Reason, []any{"broker", brokerID})
		return
	}
	defer resp.Body.Close()

	// Stream response straight through — no buffering, no cache admit.
	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, copyErr := io.Copy(w, resp.Body); copyErr != nil {
		// Connection-level error mid-stream. Headers + status already
		// written; just record it and let net/http abort the conn.
		h.opts.Logger.Warn("response stream interrupted",
			"err", copyErr.Error(), "broker", brokerID)
	}

	rec.Outcome, rec.Status = audit.OutcomeForward, resp.StatusCode
}

func (h *Handler) buildOutbound(r *http.Request, broker *profile.BrokerProfile) (*http.Request, error) {
	base := h.opts.BackendURL(broker)
	if base == nil || base.Host == "" {
		return nil, fmt.Errorf("backend URL for broker %q is empty", broker.ID)
	}

	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.URL = &url.URL{
		Scheme:   base.Scheme,
		Host:     base.Host,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}
	out.Host = base.Host
	out.Header = stripOutboundHeaders(out.Header)
	return out, nil
}

// peerSerial returns the decimal-encoded serial number of the client cert
// that authenticated this request, or "" if no client cert is present
// (e.g. plaintext httptest in unit tests).
func peerSerial(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return r.TLS.PeerCertificates[0].SerialNumber.Text(10)
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, status int, reason string, fields []any) {
	args := []any{
		"status", status,
		"method", r.Method,
		"path", r.URL.Path,
		"reason", reason,
	}
	args = append(args, fields...)
	h.opts.Logger.Warn("proxy reject", args...)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q}`+"\n", reason)
}

// hopByHopHeaders must not be forwarded by a proxy (RFC 7230 §6.1).
var hopByHopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive",
	"Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// internalHeaders are proxy-control headers consumed at this hop only.
// X-Tesseract-Idempotency-Key is *forwarded* upstream — the broker may
// honour it via its own deduplication. We don't strip it.
var internalHeaders = []string{
	HeaderBroker,
}

func stripOutboundHeaders(h http.Header) http.Header {
	out := cloneHeader(h)
	for _, name := range hopByHopHeaders {
		out.Del(name)
	}
	for _, name := range internalHeaders {
		out.Del(name)
	}
	for _, c := range h.Values("Connection") {
		for _, name := range strings.Split(c, ",") {
			if name = strings.TrimSpace(name); name != "" {
				out.Del(name)
			}
		}
	}
	return out
}

func copyResponseHeaders(dst, src http.Header) {
	for k, v := range src {
		if isHopByHop(k) {
			continue
		}
		dst[k] = append([]string(nil), v...)
	}
	for _, c := range src.Values("Connection") {
		for _, name := range strings.Split(c, ",") {
			if name = strings.TrimSpace(name); name != "" {
				dst.Del(name)
			}
		}
	}
}

func isHopByHop(name string) bool {
	for _, h := range hopByHopHeaders {
		if strings.EqualFold(h, name) {
			return true
		}
	}
	return false
}

func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, v := range h {
		out[k] = append([]string(nil), v...)
	}
	return out
}
