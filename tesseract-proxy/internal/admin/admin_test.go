package admin_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
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
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.yaml")
	sigPath := filepath.Join(dir, "bundle.yaml.sig")
	pubkeyPath := filepath.Join(dir, "pubkey.pem")
	must(t, os.WriteFile(bundlePath, []byte(bundleYAML), 0o600))
	bundleHash := sha256.Sum256([]byte(bundleYAML))
	bundleSig, err := ecdsa.SignASN1(rand.Reader, priv, bundleHash[:])
	if err != nil {
		t.Fatal(err)
	}
	must(t, os.WriteFile(sigPath, bundleSig, 0o600))
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
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

func TestAuditTail_StreamsLiveRecord(t *testing.T) {
	auditDir := t.TempDir()
	aw, err := audit.Open(audit.Options{Path: filepath.Join(auditDir, "audit.log"), RingSize: 16})
	if err != nil {
		t.Fatal(err)
	}
	defer aw.Close()

	h := admin.New(admin.Options{
		Version:   "v0.0.0-test",
		StartedAt: time.Now(),
		Holder:    profile.NewHolder(buildRouter(t)),
		Allowlist: newAllowlist(t),
		Audit:     aw,
		RoleFunc:  func(*http.Request) mtls.Role { return mtls.RoleAdmin },
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/admin/audit/tail", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}

	// Emit a record after the subscription is established.
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = aw.Log(audit.Record{
			Outcome: audit.OutcomeForward, Method: "POST", Path: "/live", Status: 200,
		})
	}()

	// Read until we see a data: line containing "/live".
	br := bufio.NewReader(resp.Body)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if strings.HasPrefix(line, "data: ") && strings.Contains(line, `"path":"/live"`) {
			return
		}
	}
	t.Fatal("did not receive live record over SSE")
}

func TestAuditTail_LastEventIDDrainsBacklog(t *testing.T) {
	auditDir := t.TempDir()
	aw, err := audit.Open(audit.Options{Path: filepath.Join(auditDir, "audit.log"), RingSize: 16})
	if err != nil {
		t.Fatal(err)
	}
	defer aw.Close()

	base := time.Now()
	for i := 0; i < 3; i++ {
		_ = aw.Log(audit.Record{
			Time: base.Add(time.Duration(i) * time.Second), Outcome: audit.OutcomeForward,
			Method: "GET", Path: "/p", Status: 200,
		})
	}
	h := admin.New(admin.Options{
		Holder:    profile.NewHolder(buildRouter(t)),
		Allowlist: newAllowlist(t),
		Audit:     aw,
		RoleFunc:  func(*http.Request) mtls.Role { return mtls.RoleAdmin },
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	// Reconnect with Last-Event-ID pointing at the first record's time.
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/admin/audit/tail", nil)
	req.Header.Set("Last-Event-ID", base.Format(time.RFC3339Nano))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Expect exactly two backlog records (strictly after base): +1s, +2s.
	br := bufio.NewReader(resp.Body)
	seen := 0
	for time.Now().Before(time.Now().Add(800 * time.Millisecond)) {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "data: ") && strings.Contains(line, `"path":"/p"`) {
			seen++
			if seen == 2 {
				return
			}
		}
	}
	if seen != 2 {
		t.Errorf("backlog records seen = %d, want 2", seen)
	}
}

func TestAuditRange_LinesTail(t *testing.T) {
	dir := t.TempDir()
	aw, err := audit.Open(audit.Options{Path: filepath.Join(dir, "audit.log"), RingSize: 4})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		_ = aw.Log(audit.Record{
			Time: time.Now().Add(time.Duration(i) * time.Millisecond),
			Outcome: audit.OutcomeForward, Method: "POST",
			Path: fmt.Sprintf("/r/%d", i), Status: 200,
		})
	}
	_ = aw.Close() // flush + release on Windows before re-opening to read

	h := admin.New(admin.Options{
		Audit: mustReopen(t, filepath.Join(dir, "audit.log")),
		Allowlist: newAllowlist(t), Holder: profile.NewHolder(buildRouter(t)),
		RoleFunc: func(*http.Request) mtls.Role { return mtls.RoleAdmin },
	})
	rec := do(t, h, "GET", "/admin/audit/range?lines=3", nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	got := strings.TrimRight(rec.Body.String(), "\n")
	lines := strings.Split(got, "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3", len(lines))
	}
	// Last three records: /r/3, /r/4, /r/5 in chronological order.
	for i, want := range []string{"/r/3", "/r/4", "/r/5"} {
		if !strings.Contains(lines[i], `"path":"`+want+`"`) {
			t.Errorf("line[%d] missing %q: %s", i, want, lines[i])
		}
	}
}

func TestAuditRange_SinceUntil(t *testing.T) {
	dir := t.TempDir()
	aw, err := audit.Open(audit.Options{Path: filepath.Join(dir, "audit.log"), RingSize: 16})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		_ = aw.Log(audit.Record{
			Time: base.Add(time.Duration(i) * time.Minute),
			Outcome: audit.OutcomeForward, Method: "POST",
			Path: fmt.Sprintf("/r/%d", i), Status: 200,
		})
	}
	_ = aw.Close()

	h := admin.New(admin.Options{
		Audit: mustReopen(t, filepath.Join(dir, "audit.log")),
		Allowlist: newAllowlist(t), Holder: profile.NewHolder(buildRouter(t)),
		RoleFunc: func(*http.Request) mtls.Role { return mtls.RoleAdmin },
	})
	// since = base+0.5min, until = base+3.5min → expect records 1, 2, 3.
	q := fmt.Sprintf("?since=%s&until=%s",
		base.Add(30*time.Second).Format(time.RFC3339Nano),
		base.Add(3*time.Minute+30*time.Second).Format(time.RFC3339Nano))
	rec := do(t, h, "GET", "/admin/audit/range"+q, nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	got := strings.TrimRight(rec.Body.String(), "\n")
	lines := strings.Split(got, "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3 (records 1-3); body=%s", len(lines), got)
	}
	for i, want := range []string{"/r/1", "/r/2", "/r/3"} {
		if !strings.Contains(lines[i], `"path":"`+want+`"`) {
			t.Errorf("line[%d] missing %q: %s", i, want, lines[i])
		}
	}
}

func TestAuditRange_NoFile(t *testing.T) {
	h := admin.New(admin.Options{
		Audit: mustReopen(t,filepath.Join(t.TempDir(), "never.log")),
		Allowlist: newAllowlist(t), Holder: profile.NewHolder(buildRouter(t)),
		RoleFunc: func(*http.Request) mtls.Role { return mtls.RoleAdmin },
	})
	// Open creates the file; remove it to exercise the IsNotExist branch.
	rec := do(t, h, "GET", "/admin/audit/range", nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestAuditRange_BadParam(t *testing.T) {
	h := admin.New(admin.Options{
		Audit: mustReopen(t,filepath.Join(t.TempDir(), "a.log")),
		Allowlist: newAllowlist(t), Holder: profile.NewHolder(buildRouter(t)),
		RoleFunc: func(*http.Request) mtls.Role { return mtls.RoleAdmin },
	})
	rec := do(t, h, "GET", "/admin/audit/range?since=not-a-time", nil)
	if rec.Code != 400 {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func mustReopen(t *testing.T, p string) *audit.Writer {
	t.Helper()
	w, err := audit.Open(audit.Options{Path: p, RingSize: 4})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

func TestLogStat(t *testing.T) {
	rec := do(t, newHandler(t, mtls.RoleAdmin, nil), "GET", "/admin/log/stat", nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["exists"] != true {
		t.Errorf("exists = %v, want true (newHandler seeds one record)", body["exists"])
	}
	if sz, _ := body["size"].(float64); sz <= 0 {
		t.Errorf("size = %v, want > 0", body["size"])
	}
}

func TestLogRotate(t *testing.T) {
	rec := do(t, newHandler(t, mtls.RoleAdmin, nil), "POST", "/admin/log/rotate", nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body["rotated_to"], "audit.log.") {
		t.Errorf("rotated_to = %q", body["rotated_to"])
	}
}

func TestLogRotate_NonAdminForbidden(t *testing.T) {
	rec := do(t, newHandler(t, mtls.RoleOrder, nil), "POST", "/admin/log/rotate", nil)
	if rec.Code != 403 {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}
