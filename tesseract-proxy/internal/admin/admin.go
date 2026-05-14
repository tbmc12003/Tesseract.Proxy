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
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
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
	mux.HandleFunc("GET /admin/audit/tail", h.guard(h.auditTail))
	mux.HandleFunc("GET /admin/audit/range", h.guard(h.auditRange))
	mux.HandleFunc("GET /admin/log/stat", h.guard(h.logStat))
	mux.HandleFunc("POST /admin/log/rotate", h.guard(h.logRotate))
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

// maxAuditRangeLines caps any /admin/audit/range response. The audit
// log is JSON-lines on disk; ~10k records typically fits in a few MB
// and keeps both the server scan and the admin-ui client bounded.
const maxAuditRangeLines = 10_000

// auditRange streams JSON-lines records from the on-disk audit log
// filtered by query params:
//
//	?lines=N           tail-N (most recent N records, chronological)
//	?since=<rfc3339>   include records with Time >  since
//	?until=<rfc3339>   include records with Time <= until
//
// `lines` and the time-range params are mutually exclusive; `lines`
// wins if both are present. Hard cap maxAuditRangeLines applies in
// every mode — newest-first for tail, oldest-first for ranges.
func (h *Handler) auditRange(w http.ResponseWriter, r *http.Request) {
	if h.opts.Audit == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "audit not configured")
		return
	}
	q := r.URL.Query()

	var (
		linesMode bool
		linesN    = maxAuditRangeLines
		since     time.Time
		until     time.Time
	)
	if s := q.Get("lines"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n <= 0 {
			writeJSONError(w, http.StatusBadRequest, "lines must be positive integer")
			return
		}
		linesMode = true
		if n < linesN {
			linesN = n
		}
	} else {
		if s := q.Get("since"); s != "" {
			t, err := time.Parse(time.RFC3339Nano, s)
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, "since: "+err.Error())
				return
			}
			since = t
		}
		if s := q.Get("until"); s != "" {
			t, err := time.Parse(time.RFC3339Nano, s)
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, "until: "+err.Error())
				return
			}
			until = t
		}
	}

	f, err := os.Open(h.opts.Audit.Path())
	if err != nil {
		if os.IsNotExist(err) {
			// Pre-bootstrap state: no log file yet → empty JSON-lines.
			w.Header().Set("Content-Type", "application/x-ndjson")
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)

	if linesMode {
		// Keep the last N lines in a ring, then emit. Cheaper than
		// seek-from-end for files of a few MB; the SC ceiling above
		// caps any single record at 1 MiB.
		ring := make([][]byte, linesN)
		head, count := 0, 0
		for sc.Scan() {
			// Copy — scanner reuses its buffer.
			ring[head] = append(ring[head][:0], sc.Bytes()...)
			head = (head + 1) % linesN
			if count < linesN {
				count++
			}
		}
		start := (head - count + linesN) % linesN
		for i := 0; i < count; i++ {
			w.Write(ring[(start+i)%linesN])
			w.Write([]byte{'\n'})
		}
		return
	}

	// Range mode. Stream-filter, cap at maxAuditRangeLines.
	emitted := 0
	for sc.Scan() {
		if emitted >= maxAuditRangeLines {
			break
		}
		var rec audit.Record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			continue // skip malformed lines silently
		}
		if !since.IsZero() && !rec.Time.After(since) {
			continue
		}
		if !until.IsZero() && rec.Time.After(until) {
			continue
		}
		w.Write(sc.Bytes())
		w.Write([]byte{'\n'})
		emitted++
	}
}

// logStat reports the current on-disk audit log size + mtime.
// Surfaces "missing file" as 200 with size=0 + path so the UI can
// distinguish pre-bootstrap vs an actual error.
func (h *Handler) logStat(w http.ResponseWriter, _ *http.Request) {
	if h.opts.Audit == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "audit not configured")
		return
	}
	size, mtime, err := h.opts.Audit.Stat()
	if err != nil && !os.IsNotExist(err) {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := map[string]any{
		"path":    h.opts.Audit.Path(),
		"size":    size,
		"mtime":   mtime,
		"exists":  err == nil,
	}
	writeJSON(w, http.StatusOK, out)
}

// logRotate forces an immediate rotation of the audit log. The current
// file is renamed to <path>.<utc-timestamp> and a fresh file is opened
// at the original path. Returns the rotated-to path so the operator can
// confirm in the UI.
func (h *Handler) logRotate(w http.ResponseWriter, _ *http.Request) {
	if h.opts.Audit == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "audit not configured")
		return
	}
	rotated, err := h.opts.Audit.Rotate()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"rotated_to": rotated})
}

// auditTail implements Server-Sent Events live tail of audit records.
// Reconnects: clients send Last-Event-ID with the rfc3339nano timestamp
// of the last record they saw; the handler drains any strictly-newer
// records from the in-memory ring before switching to live fan-out.
// Heartbeats: a `:` comment line every 15 s keeps middleboxes from
// closing idle connections.
func (h *Handler) auditTail(w http.ResponseWriter, r *http.Request) {
	if h.opts.Audit == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "audit not configured")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	var after time.Time
	if last := r.Header.Get("Last-Event-ID"); last != "" {
		if t, err := time.Parse(time.RFC3339Nano, last); err == nil {
			after = t
		}
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	sub := h.opts.Audit.Subscribe(0, after)
	defer sub.Close()

	emit := func(rec audit.Record) error {
		data, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "id: %s\ndata: %s\n\n",
			rec.Time.Format(time.RFC3339Nano), data); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}
	emitDropped := func(n int64) {
		fmt.Fprintf(w, "event: dropped\ndata: {\"count\":%d}\n\n", n)
		flusher.Flush()
	}

	for _, rec := range sub.Backlog {
		if err := emit(rec); err != nil {
			return
		}
	}

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		if n := sub.DroppedAndReset(); n > 0 {
			emitDropped(n)
		}
		select {
		case <-r.Context().Done():
			return
		case rec, ok := <-sub.Ch:
			if !ok {
				return
			}
			if err := emit(rec); err != nil {
				return
			}
		case <-heartbeat.C:
			if _, err := w.Write([]byte(": heartbeat\n\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
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
