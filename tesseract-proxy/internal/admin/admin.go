// Package admin implements the /admin/* management surface (arch §14.1).
//
// All endpoints share a single mTLS listener with the order plane and are
// gated by the admin-serial allowlist via mtls.PeerRole — there is no
// anonymous access anywhere, not even /admin/healthz. A custom RoleFunc
// can be injected for unit tests; production wires it through the live
// Allowlist.
//
// Endpoints (P2.10):
//
//	GET  /admin/healthz                 liveness; mTLS required
//	GET  /admin/status                  version, uptime, bundle, cache stats
//	GET  /admin/profiles                broker profiles from the live bundle
//	GET  /admin/audit/recent?n=…        last N audit records (default 100)
//	GET  /admin/metrics                 Prometheus exposition
//	POST /admin/bundle/reload           force pull-and-reload (caller supplies)
//	POST /admin/cert/rotate-server      stub; full impl is P6.1
//	POST /admin/client-serials          replace order/admin serial allowlists
package admin

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/equinomics/tesseract-proxy/internal/audit"
	"github.com/equinomics/tesseract-proxy/internal/metrics"
	"github.com/equinomics/tesseract-proxy/internal/mtls"
	"github.com/equinomics/tesseract-proxy/internal/profile"
)

// maxBinaryUploadBytes caps the proxy binary upload size. The current
// arm64 build is ~3 MB stripped; we allow up to 32 MB to leave headroom
// for symbols / future growth.
const maxBinaryUploadBytes = 32 << 20

// Options configures a Handler. Allowlist is required so role
// classification has somewhere to ask; everything else is optional and
// the corresponding endpoints degrade clearly when omitted.
type Options struct {
	Version   string
	StartedAt time.Time

	Holder    *profile.Holder
	Allowlist *mtls.Allowlist
	Audit     *audit.Writer
	Metrics   *metrics.Counters

	// ReloadBundle, when non-nil, is called by POST /admin/bundle/reload.
	// Wiring lives in cmd/proxy/main.go (the only place that knows how to
	// re-fetch + verify + swap the Router via Holder.Store).
	ReloadBundle func() error

	// AcceptBinary, when non-nil, is called by POST /admin/binary/upload
	// (P2.12) with the uploaded binary and signature. Implementations
	// (typically internal/binupd.Receiver.Apply) are responsible for
	// signature verification + atomic file swap. After this returns nil,
	// cmd/proxy/main.go is expected to schedule a graceful restart.
	AcceptBinary func(binary, signature []byte) error

	// RoleFunc classifies the calling peer. Default: look up the client
	// cert serial in Allowlist. Tests inject a stub.
	RoleFunc func(*http.Request) mtls.Role

	// Logger is the slog sink for panic-recovery and audit messages.
	// Defaults to slog.Default.
	Logger *slog.Logger
}

// Handler is the /admin/* HTTP handler. It is an http.Handler and can be
// composed under any outer mux that wishes to route /admin/* to it.
type Handler struct {
	opts Options
	mux  *http.ServeMux
}

// New constructs an admin Handler.
func New(opts Options) *Handler {
	if opts.RoleFunc == nil {
		al := opts.Allowlist
		opts.RoleFunc = func(r *http.Request) mtls.Role {
			return mtls.PeerRole(al, r.TLS)
		}
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	h := &Handler{opts: opts}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/healthz", h.guard(h.healthz))
	mux.HandleFunc("GET /admin/status", h.guard(h.status))
	mux.HandleFunc("GET /admin/profiles", h.guard(h.profiles))
	mux.HandleFunc("GET /admin/audit/recent", h.guard(h.auditRecent))
	mux.HandleFunc("GET /admin/metrics", h.guard(h.metrics))
	mux.HandleFunc("POST /admin/bundle/reload", h.guard(h.bundleReload))
	mux.HandleFunc("POST /admin/cert/rotate-server", h.guard(h.rotateServer))
	mux.HandleFunc("POST /admin/client-serials", h.guard(h.clientSerials))
	mux.HandleFunc("POST /admin/binary/upload", h.guard(h.binaryUpload))
	h.mux = mux
	return h
}

// ServeHTTP dispatches to the per-endpoint handlers via the internal
// mux, wrapped in panic recovery (P2.15). Any panic produces a 500 and a
// structured error log; the connection is not torn down by net/http's
// own panic logging.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if p := recover(); p != nil {
			h.opts.Logger.Error("admin panic recovered",
				"panic", fmt.Sprintf("%v", p),
				"method", r.Method, "path", r.URL.Path)
			writeJSONError(w, http.StatusInternalServerError, "internal server error")
		}
	}()
	h.mux.ServeHTTP(w, r)
}

// guard enforces the admin-role check before handing off to next.
func (h *Handler) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.opts.RoleFunc(r).Allows(mtls.RoleAdmin) {
			writeJSONError(w, http.StatusForbidden, "admin role required")
			return
		}
		next(w, r)
	}
}

func (h *Handler) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type brokerSummary struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Host        string `json:"host"`
	Enabled     bool   `json:"enabled"`
	Endpoints   int    `json:"endpoints"`
}

func (h *Handler) status(w http.ResponseWriter, _ *http.Request) {
	router := h.opts.Holder.Load()
	out := map[string]any{
		"version":        h.opts.Version,
		"uptime_seconds": int(time.Since(h.opts.StartedAt).Seconds()),
	}
	if router != nil {
		summaries := []brokerSummary{}
		for _, b := range router.Brokers() {
			summaries = append(summaries, brokerSummary{
				ID:          b.ID,
				DisplayName: b.DisplayName,
				Host:        b.Host,
				Enabled:     b.Enabled,
				Endpoints:   len(b.OrderEndpoints),
			})
		}
		out["bundle_version"] = router.BundleVersion()
		out["brokers"] = summaries
	} else {
		out["bundle_version"] = ""
		out["brokers"] = []brokerSummary{}
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) profiles(w http.ResponseWriter, _ *http.Request) {
	router := h.opts.Holder.Load()
	if router == nil {
		writeJSON(w, http.StatusOK, []*profile.BrokerProfile{})
		return
	}
	writeJSON(w, http.StatusOK, router.Brokers())
}

func (h *Handler) auditRecent(w http.ResponseWriter, r *http.Request) {
	if h.opts.Audit == nil {
		writeJSON(w, http.StatusOK, []audit.Record{})
		return
	}
	n := 100
	if q := r.URL.Query().Get("n"); q != "" {
		if parsed, err := strconv.Atoi(q); err == nil && parsed > 0 {
			n = parsed
		}
	}
	writeJSON(w, http.StatusOK, h.opts.Audit.Recent(n))
}

func (h *Handler) metrics(w http.ResponseWriter, _ *http.Request) {
	m := h.opts.Metrics
	if m == nil {
		m = &metrics.Counters{}
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(m.Render()))
}

func (h *Handler) bundleReload(w http.ResponseWriter, _ *http.Request) {
	if h.opts.ReloadBundle == nil {
		writeJSONError(w, http.StatusNotImplemented, "bundle reload not configured")
		return
	}
	if err := h.opts.ReloadBundle(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "reloaded"})
}

func (h *Handler) rotateServer(w http.ResponseWriter, _ *http.Request) {
	// Full implementation is P6.1 (cert lifecycle). Stub returns 501
	// rather than 404 so the endpoint surface is discoverable without
	// pretending the feature is missing.
	writeJSONError(w, http.StatusNotImplemented,
		"server cert rotation not yet implemented (P6.1)")
}

type clientSerialsRequest struct {
	Order []string `json:"order"`
	Admin []string `json:"admin"`
}

// binaryUpload reads a multipart form with two parts — "binary" and
// "signature" — and hands them to AcceptBinary. Successful upload returns
// 200 with `{"status":"staged"}`; the caller is expected to trigger a
// graceful restart after the response is flushed.
func (h *Handler) binaryUpload(w http.ResponseWriter, r *http.Request) {
	if h.opts.AcceptBinary == nil {
		writeJSONError(w, http.StatusNotImplemented, "binary upload not configured")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBinaryUploadBytes)
	if err := r.ParseMultipartForm(maxBinaryUploadBytes); err != nil {
		writeJSONError(w, http.StatusBadRequest, "parse multipart: "+err.Error())
		return
	}
	binBytes, err := readPart(r, "binary")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	sigBytes, err := readPart(r, "signature")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.opts.AcceptBinary(binBytes, sigBytes); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "staged"})
}

func readPart(r *http.Request, name string) ([]byte, error) {
	fh, _, err := r.FormFile(name)
	if err != nil {
		return nil, fmt.Errorf("missing form file %q: %w", name, err)
	}
	defer fh.Close()
	data, err := io.ReadAll(fh)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", name, err)
	}
	return data, nil
}

func (h *Handler) clientSerials(w http.ResponseWriter, r *http.Request) {
	if h.opts.Allowlist == nil {
		writeJSONError(w, http.StatusInternalServerError, "no allowlist configured")
		return
	}
	var req clientSerialsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if err := h.opts.Allowlist.Replace(req.Order, req.Admin); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q}`+"\n", msg)
}
