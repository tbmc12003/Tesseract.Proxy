package proxy_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/equinomics/tesseract-proxy/internal/audit"
	"github.com/equinomics/tesseract-proxy/internal/profile"
	"github.com/equinomics/tesseract-proxy/internal/proxy"
)

const testBundle = `schema_version: 1
bundle_version: 2026-05-13-001
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
      per_user_rps: 100
      per_user_burst: 200

  - id: disabledbroker
    display_name: Disabled (Test)
    host: disabled.local
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
      per_user_rps: 1
      per_user_burst: 1
`

func buildRouter(t *testing.T) *profile.Router {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.yaml")
	sigPath := filepath.Join(dir, "bundle.yaml.sig")
	pubkeyPath := filepath.Join(dir, "pubkey.pem")
	if err := os.WriteFile(bundlePath, []byte(testBundle), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, ed25519.Sign(priv, []byte(testBundle)), 0o600); err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubkeyPath,
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := profile.LoadAndVerify(profile.LoadOptions{
		BundlePath: bundlePath, SigPath: sigPath, PubkeyPath: pubkeyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	return res.Router
}

type fakeBroker struct {
	srv     *httptest.Server
	called  atomic.Int64
	lastReq atomic.Pointer[http.Request]
}

func newFakeBroker(t *testing.T, handler http.HandlerFunc) *fakeBroker {
	t.Helper()
	fb := &fakeBroker{}
	fb.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fb.called.Add(1)
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		rc := r.Clone(r.Context())
		rc.Body = io.NopCloser(strings.NewReader(string(body)))
		fb.lastReq.Store(rc)
		handler(w, r)
	}))
	t.Cleanup(fb.srv.Close)
	return fb
}

func newHandler(t *testing.T, fb *fakeBroker) *proxy.Handler {
	t.Helper()
	backendURL, _ := url.Parse(fb.srv.URL)
	h, err := proxy.New(proxy.Options{
		Holder:    profile.NewHolder(buildRouter(t)),
		Transport: http.DefaultTransport,
		BackendURL: func(*profile.BrokerProfile) *url.URL {
			return &url.URL{Scheme: backendURL.Scheme, Host: backendURL.Host}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func doRequest(t *testing.T, h http.Handler, method, path string, headers map[string]string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func echo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Broker-Marker", "from-papertrader")
	w.WriteHeader(http.StatusCreated)
	_, _ = io.WriteString(w, `{"data":{"orderNumber":"OID-12345"}}`)
}

// --- place / modify / cancel each forward unchanged ---

func TestForward_Place(t *testing.T) {
	t.Parallel()
	fb := newFakeBroker(t, echo)
	h := newHandler(t, fb)
	rec := doRequest(t, h, "POST", "/Orders/2.0/quick/order/rule/ms/place",
		map[string]string{proxy.HeaderBroker: "papertrader"},
		`{"symbol":"RELIANCE","qty":1}`)
	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", rec.Code)
	}
	if got := rec.Header().Get("X-Broker-Marker"); got != "from-papertrader" {
		t.Errorf("broker marker dropped: %q", got)
	}
	if !strings.Contains(rec.Body.String(), `"OID-12345"`) {
		t.Errorf("body not forwarded unchanged: %q", rec.Body.String())
	}
	if fb.called.Load() != 1 {
		t.Errorf("broker called %d times, want 1", fb.called.Load())
	}
}

func TestForward_Modify(t *testing.T) {
	t.Parallel()
	fb := newFakeBroker(t, echo)
	rec := doRequest(t, newHandler(t, fb), "POST", "/Orders/2.0/quick/order/vr/modify",
		map[string]string{proxy.HeaderBroker: "papertrader"}, `{"qty":2}`)
	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", rec.Code)
	}
}

func TestForward_Cancel(t *testing.T) {
	t.Parallel()
	fb := newFakeBroker(t, echo)
	rec := doRequest(t, newHandler(t, fb), "POST", "/Orders/2.0/quick/order/cancel",
		map[string]string{proxy.HeaderBroker: "papertrader"}, `{"orderId":"OID-12345"}`)
	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", rec.Code)
	}
}

// --- reject paths ---

func TestReject_MissingBrokerHeader(t *testing.T) {
	t.Parallel()
	fb := newFakeBroker(t, echo)
	rec := doRequest(t, newHandler(t, fb), "POST", "/Orders/2.0/quick/order/cancel", nil, "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if fb.called.Load() != 0 {
		t.Errorf("broker should not have been called")
	}
}

func TestReject_UnknownBroker(t *testing.T) {
	t.Parallel()
	fb := newFakeBroker(t, echo)
	rec := doRequest(t, newHandler(t, fb), "POST", "/Orders/2.0/quick/order/cancel",
		map[string]string{proxy.HeaderBroker: "ghostbroker"}, "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestReject_DisabledBroker(t *testing.T) {
	t.Parallel()
	fb := newFakeBroker(t, echo)
	rec := doRequest(t, newHandler(t, fb), "POST", "/Orders/2.0/quick/order/rule/ms/place",
		map[string]string{proxy.HeaderBroker: "disabledbroker"}, "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for disabled broker", rec.Code)
	}
}

func TestReject_WrongMethod(t *testing.T) {
	t.Parallel()
	fb := newFakeBroker(t, echo)
	rec := doRequest(t, newHandler(t, fb), "GET", "/Orders/2.0/quick/order/cancel",
		map[string]string{proxy.HeaderBroker: "papertrader"}, "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestReject_UnknownPath(t *testing.T) {
	t.Parallel()
	fb := newFakeBroker(t, echo)
	rec := doRequest(t, newHandler(t, fb), "POST", "/positions/exit",
		map[string]string{proxy.HeaderBroker: "papertrader"}, "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if fb.called.Load() != 0 {
		t.Errorf("disallowed path must not reach broker")
	}
}

// --- header hygiene ---

func TestInternalBrokerHeaderStripped(t *testing.T) {
	t.Parallel()
	fb := newFakeBroker(t, echo)
	doRequest(t, newHandler(t, fb), "POST", "/Orders/2.0/quick/order/rule/ms/place",
		map[string]string{
			proxy.HeaderBroker:     "papertrader",
			"X-Forwarded-Customer": "preserved",
		}, "{}")
	got := fb.lastReq.Load()
	if got == nil {
		t.Fatal("broker not called")
	}
	if v := got.Header.Get(proxy.HeaderBroker); v != "" {
		t.Errorf("X-Tesseract-Broker leaked upstream: %q", v)
	}
	if v := got.Header.Get("X-Forwarded-Customer"); v != "preserved" {
		t.Errorf("non-internal header dropped: %q", v)
	}
}

func TestIdempotencyKeyForwardedUpstream(t *testing.T) {
	t.Parallel()
	// X-Tesseract-Idempotency-Key is forwarded — the broker may honour it
	// via its own deduplication (Fyers' orderTag, etc.). The proxy doesn't
	// interpret it.
	fb := newFakeBroker(t, echo)
	doRequest(t, newHandler(t, fb), "POST", "/Orders/2.0/quick/order/rule/ms/place",
		map[string]string{
			proxy.HeaderBroker:         "papertrader",
			proxy.HeaderIdempotencyKey: "uuid-xyz",
		}, "{}")
	got := fb.lastReq.Load()
	if got == nil {
		t.Fatal("broker not called")
	}
	if v := got.Header.Get(proxy.HeaderIdempotencyKey); v != "uuid-xyz" {
		t.Errorf("idempotency key NOT forwarded upstream: %q", v)
	}
}

func TestHopByHopStripped(t *testing.T) {
	t.Parallel()
	fb := newFakeBroker(t, echo)
	doRequest(t, newHandler(t, fb), "POST", "/Orders/2.0/quick/order/rule/ms/place",
		map[string]string{
			proxy.HeaderBroker: "papertrader",
			"Keep-Alive":       "timeout=5",
			"Connection":       "Keep-Alive, X-Custom-Hop",
			"X-Custom-Hop":     "should-be-removed",
		}, "")
	got := fb.lastReq.Load()
	if got == nil {
		t.Fatal("broker not called")
	}
	if v := got.Header.Get("Keep-Alive"); v != "" {
		t.Errorf("Keep-Alive leaked: %q", v)
	}
	if v := got.Header.Get("X-Custom-Hop"); v != "" {
		t.Errorf("Connection-named header X-Custom-Hop leaked: %q", v)
	}
}

// --- upstream / lifecycle paths ---

func TestUpstreamError_502(t *testing.T) {
	t.Parallel()
	fb := newFakeBroker(t, func(http.ResponseWriter, *http.Request) {})
	fb.srv.Close() // force dial failures
	backendURL, _ := url.Parse(fb.srv.URL)
	h, err := proxy.New(proxy.Options{
		Holder:    profile.NewHolder(buildRouter(t)),
		Transport: http.DefaultTransport,
		BackendURL: func(*profile.BrokerProfile) *url.URL {
			return &url.URL{Scheme: backendURL.Scheme, Host: backendURL.Host}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := doRequest(t, h, "POST", "/Orders/2.0/quick/order/rule/ms/place",
		map[string]string{proxy.HeaderBroker: "papertrader"}, "")
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

func TestNoBundleLoaded_503(t *testing.T) {
	t.Parallel()
	h, err := proxy.New(proxy.Options{
		Holder:    profile.NewHolder(nil),
		Transport: http.DefaultTransport,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := doRequest(t, h, "POST", "/Orders/2.0/quick/order/rule/ms/place",
		map[string]string{proxy.HeaderBroker: "papertrader"}, "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

func TestNew_RejectsBadOptions(t *testing.T) {
	t.Parallel()
	if _, err := proxy.New(proxy.Options{}); err == nil {
		t.Error("expected error: missing Holder")
	}
	if _, err := proxy.New(proxy.Options{Holder: profile.NewHolder(nil)}); err == nil {
		t.Error("expected error: missing Transport")
	}
}

// --- audit emission ---

func TestAuditEmission_ForwardAndReject(t *testing.T) {
	t.Parallel()
	fb := newFakeBroker(t, echo)
	backendURL, _ := url.Parse(fb.srv.URL)
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	aw, err := audit.Open(audit.Options{Path: auditPath, RingSize: 16})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = aw.Close() })

	h, err := proxy.New(proxy.Options{
		Holder:    profile.NewHolder(buildRouter(t)),
		Transport: http.DefaultTransport,
		Audit:     aw,
		BackendURL: func(*profile.BrokerProfile) *url.URL {
			return &url.URL{Scheme: backendURL.Scheme, Host: backendURL.Host}
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	doRequest(t, h, "POST", "/Orders/2.0/quick/order/rule/ms/place",
		map[string]string{proxy.HeaderBroker: "papertrader", proxy.HeaderIdempotencyKey: "uuid-aud"},
		`{"q":1}`)
	doRequest(t, h, "POST", "/Orders/2.0/quick/order/rule/ms/place",
		map[string]string{proxy.HeaderBroker: "ghost"}, "")

	got := aw.Recent(10)
	if len(got) != 2 {
		t.Fatalf("got %d audit records, want 2", len(got))
	}
	if got[0].Outcome != audit.OutcomeForward ||
		got[0].IdempotencyKey != "uuid-aud" || got[0].BrokerID != "papertrader" {
		t.Errorf("forward record wrong: %+v", got[0])
	}
	if got[1].Outcome != audit.OutcomeReject || got[1].Status != http.StatusForbidden ||
		got[1].BrokerID != "ghost" {
		t.Errorf("reject record wrong: %+v", got[1])
	}
}

// --- panic recovery ---

// rtPanic is a RoundTripper that panics — exercises the recover defer.
type rtPanic struct{}

func (rtPanic) RoundTrip(*http.Request) (*http.Response, error) {
	panic("transport blew up")
}

func TestPanicRecovery_Returns500AndAudits(t *testing.T) {
	t.Parallel()
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	aw, err := audit.Open(audit.Options{Path: auditPath, RingSize: 4})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = aw.Close() })

	h, err := proxy.New(proxy.Options{
		Holder:    profile.NewHolder(buildRouter(t)),
		Transport: rtPanic{},
		Audit:     aw,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := doRequest(t, h, "POST", "/Orders/2.0/quick/order/rule/ms/place",
		map[string]string{proxy.HeaderBroker: "papertrader"}, "")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 after panic", rec.Code)
	}
	recent := aw.Recent(2)
	if len(recent) != 1 ||
		recent[0].Outcome != audit.OutcomeUpstreamErr ||
		!strings.Contains(recent[0].Reason, "panic") {
		t.Errorf("panic record wrong: %+v", recent)
	}
}
