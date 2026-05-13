package admin_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/equinomics/tesseract-proxy/internal/admin"
	"github.com/equinomics/tesseract-proxy/internal/audit"
	"github.com/equinomics/tesseract-proxy/internal/metrics"
	"github.com/equinomics/tesseract-proxy/internal/mtls"
	"github.com/equinomics/tesseract-proxy/internal/profile"
)

const bundleYAML = `schema_version: 1
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
    idempotency:
      client_order_id_header: X-Client-Order-Id
      client_order_id_body_path: ""
      echo_in_response_path: data.orderNumber
    rate_limit:
      per_user_rps: 5
      per_user_burst: 10
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
	must(t, os.WriteFile(bundlePath, []byte(bundleYAML), 0o600))
	must(t, os.WriteFile(sigPath, ed25519.Sign(priv, []byte(bundleYAML)), 0o600))
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	must(t, os.WriteFile(pubkeyPath,
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600))
	res, err := profile.LoadAndVerify(profile.LoadOptions{
		BundlePath: bundlePath, SigPath: sigPath, PubkeyPath: pubkeyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	return res.Router
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func newAllowlist(t *testing.T) *mtls.Allowlist {
	t.Helper()
	al, err := mtls.NewAllowlist(mtls.Options{
		AllowedOrderSerials: []string{"1001"},
		AllowedAdminSerials: []string{"2001"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return al
}

func newHandler(t *testing.T, role mtls.Role, override func(*admin.Options)) http.Handler {
	t.Helper()
	auditDir := t.TempDir()
	aw, err := audit.Open(audit.Options{Path: filepath.Join(auditDir, "audit.log"), RingSize: 16})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = aw.Close() })
	_ = aw.Log(audit.Record{
		Outcome: audit.OutcomeForward, Method: "POST", Path: "/x", Status: 200, LatencyMs: 5,
	})

	opts := admin.Options{
		Version:   "v1.2.3",
		StartedAt: time.Now().Add(-30 * time.Second),
		Holder:    profile.NewHolder(buildRouter(t)),
		Allowlist: newAllowlist(t),
		Audit:     aw,
		Metrics:   &metrics.Counters{},
		RoleFunc:  func(*http.Request) mtls.Role { return role },
	}
	if override != nil {
		override(&opts)
	}
	return admin.New(opts)
}

func do(t *testing.T, h http.Handler, method, target string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHealthz_AdminOK(t *testing.T) {
	t.Parallel()
	rec := do(t, newHandler(t, mtls.RoleAdmin, nil), "GET", "/admin/healthz", nil)
	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestHealthz_NonAdminForbidden(t *testing.T) {
	t.Parallel()
	rec := do(t, newHandler(t, mtls.RoleOrder, nil), "GET", "/admin/healthz", nil)
	if rec.Code != 403 {
		t.Errorf("order role got status %d, want 403", rec.Code)
	}
}

func TestHealthz_NoneRoleForbidden(t *testing.T) {
	t.Parallel()
	rec := do(t, newHandler(t, mtls.RoleNone, nil), "GET", "/admin/healthz", nil)
	if rec.Code != 403 {
		t.Errorf("none role got status %d, want 403", rec.Code)
	}
}

func TestStatus(t *testing.T) {
	t.Parallel()
	rec := do(t, newHandler(t, mtls.RoleAdmin, nil), "GET", "/admin/status", nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["version"] != "v1.2.3" {
		t.Errorf("version: %v", body["version"])
	}
	if body["bundle_version"] != "2026-05-13-001" {
		t.Errorf("bundle_version: %v", body["bundle_version"])
	}
	if up, _ := body["uptime_seconds"].(float64); up < 1 {
		t.Errorf("uptime_seconds = %v, expected >= 1", body["uptime_seconds"])
	}
	brokers, _ := body["brokers"].([]any)
	if len(brokers) != 1 {
		t.Errorf("brokers length = %d, want 1", len(brokers))
	}
}

func TestProfiles(t *testing.T) {
	t.Parallel()
	rec := do(t, newHandler(t, mtls.RoleAdmin, nil), "GET", "/admin/profiles", nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	var body []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body) != 1 || body[0]["id"] != "papertrader" {
		t.Errorf("profiles body: %+v", body)
	}
}

func TestAuditRecent(t *testing.T) {
	t.Parallel()
	rec := do(t, newHandler(t, mtls.RoleAdmin, nil), "GET", "/admin/audit/recent?n=5", nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	var body []audit.Record
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body) != 1 {
		t.Errorf("audit records = %d, want 1 (seed)", len(body))
	}
}

func TestMetrics_PrometheusFormat(t *testing.T) {
	t.Parallel()
	h := newHandler(t, mtls.RoleAdmin, func(o *admin.Options) {
		o.Metrics.Forwards.Store(42)
		o.Metrics.Rejects.Store(3)
	})
	rec := do(t, h, "GET", "/admin/metrics", nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain*", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"# TYPE tesseract_forwards_total counter",
		"tesseract_forwards_total 42",
		"tesseract_rejects_total 3",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics body missing %q\n--- body ---\n%s", want, body)
		}
	}
}

func TestBundleReload_NotConfigured(t *testing.T) {
	t.Parallel()
	rec := do(t, newHandler(t, mtls.RoleAdmin, nil), "POST", "/admin/bundle/reload", nil)
	if rec.Code != 501 {
		t.Errorf("status = %d, want 501", rec.Code)
	}
}

func TestBundleReload_CallsHook(t *testing.T) {
	t.Parallel()
	var called atomic.Int64
	h := newHandler(t, mtls.RoleAdmin, func(o *admin.Options) {
		o.ReloadBundle = func() error {
			called.Add(1)
			return nil
		}
	})
	rec := do(t, h, "POST", "/admin/bundle/reload", nil)
	if rec.Code != 200 || called.Load() != 1 {
		t.Errorf("status=%d called=%d", rec.Code, called.Load())
	}
}

func TestBundleReload_HookErrorIs500(t *testing.T) {
	t.Parallel()
	h := newHandler(t, mtls.RoleAdmin, func(o *admin.Options) {
		o.ReloadBundle = func() error { return errors.New("bad signature") }
	})
	rec := do(t, h, "POST", "/admin/bundle/reload", nil)
	if rec.Code != 500 {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "bad signature") {
		t.Errorf("error not surfaced: %s", rec.Body.String())
	}
}

func TestRotateServer_StubReturns501(t *testing.T) {
	t.Parallel()
	rec := do(t, newHandler(t, mtls.RoleAdmin, nil), "POST", "/admin/cert/rotate-server", nil)
	if rec.Code != 501 {
		t.Errorf("status = %d, want 501", rec.Code)
	}
}

func TestClientSerials_UpdatesAllowlist(t *testing.T) {
	t.Parallel()
	al := newAllowlist(t)
	h := newHandler(t, mtls.RoleAdmin, func(o *admin.Options) {
		o.Allowlist = al
	})
	body := strings.NewReader(`{"order":["5000"],"admin":["6000"]}`)
	rec := do(t, h, "POST", "/admin/client-serials", body)
	if rec.Code != 200 {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if al.Classify(big.NewInt(5000)) != mtls.RoleOrder {
		t.Errorf("5000 not classified as order after Replace")
	}
	if al.Classify(big.NewInt(6000)) != mtls.RoleAdmin {
		t.Errorf("6000 not classified as admin after Replace")
	}
	if al.Classify(big.NewInt(1001)) != mtls.RoleNone {
		t.Errorf("old order serial 1001 should now be unallowed")
	}
}

func TestClientSerials_BadJSON(t *testing.T) {
	t.Parallel()
	rec := do(t, newHandler(t, mtls.RoleAdmin, nil), "POST", "/admin/client-serials",
		strings.NewReader("{not json"))
	if rec.Code != 400 {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestClientSerials_InvalidSerial(t *testing.T) {
	t.Parallel()
	rec := do(t, newHandler(t, mtls.RoleAdmin, nil), "POST", "/admin/client-serials",
		strings.NewReader(`{"order":["not-a-number"],"admin":[]}`))
	if rec.Code != 400 {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func buildBinaryMultipart(t *testing.T, bin, sig []byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	binW, err := mw.CreateFormFile("binary", "proxy")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := binW.Write(bin); err != nil {
		t.Fatal(err)
	}
	sigW, err := mw.CreateFormFile("signature", "proxy.sig")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sigW.Write(sig); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf, mw.FormDataContentType()
}

func doMultipart(t *testing.T, h http.Handler, target string, body *bytes.Buffer, ct string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", target, body)
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestBinaryUpload_NotConfigured(t *testing.T) {
	t.Parallel()
	body, ct := buildBinaryMultipart(t, []byte("bin"), []byte("sig"))
	rec := doMultipart(t, newHandler(t, mtls.RoleAdmin, nil), "/admin/binary/upload", body, ct)
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", rec.Code)
	}
}

func TestBinaryUpload_AcceptSucceeds(t *testing.T) {
	t.Parallel()
	var gotBin, gotSig []byte
	h := newHandler(t, mtls.RoleAdmin, func(o *admin.Options) {
		o.AcceptBinary = func(binary, signature []byte) error {
			gotBin = append([]byte(nil), binary...)
			gotSig = append([]byte(nil), signature...)
			return nil
		}
	})
	body, ct := buildBinaryMultipart(t, []byte("proxy-v2-bytes"), []byte("the-sig"))
	rec := doMultipart(t, h, "/admin/binary/upload", body, ct)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if string(gotBin) != "proxy-v2-bytes" || string(gotSig) != "the-sig" {
		t.Errorf("hook received wrong bytes: bin=%q sig=%q", gotBin, gotSig)
	}
}

func TestBinaryUpload_AcceptError(t *testing.T) {
	t.Parallel()
	h := newHandler(t, mtls.RoleAdmin, func(o *admin.Options) {
		o.AcceptBinary = func(_, _ []byte) error { return errors.New("bad sig") }
	})
	body, ct := buildBinaryMultipart(t, []byte("bin"), []byte("sig"))
	rec := doMultipart(t, h, "/admin/binary/upload", body, ct)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "bad sig") {
		t.Errorf("reason not surfaced: %s", rec.Body.String())
	}
}

func TestBinaryUpload_NonAdminForbidden(t *testing.T) {
	t.Parallel()
	body, ct := buildBinaryMultipart(t, []byte("bin"), []byte("sig"))
	rec := doMultipart(t, newHandler(t, mtls.RoleOrder, func(o *admin.Options) {
		o.AcceptBinary = func(_, _ []byte) error { return nil }
	}), "/admin/binary/upload", body, ct)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestPanicRecovery_Returns500(t *testing.T) {
	t.Parallel()
	h := newHandler(t, mtls.RoleAdmin, func(o *admin.Options) {
		// RoleFunc panics — the recover defer should catch and return 500.
		o.RoleFunc = func(*http.Request) mtls.Role { panic("role classifier blew up") }
	})
	rec := do(t, h, "GET", "/admin/status", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 after panic", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "internal server error") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestUnknownPath_404(t *testing.T) {
	t.Parallel()
	rec := do(t, newHandler(t, mtls.RoleAdmin, nil), "GET", "/admin/bogus", nil)
	if rec.Code != 404 {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestMethodMismatch_405(t *testing.T) {
	t.Parallel()
	rec := do(t, newHandler(t, mtls.RoleAdmin, nil), "POST", "/admin/healthz", nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}
