package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// auditHandler proxies the SSE stream from the proxy's
// GET /admin/audit/tail down to a browser EventSource over loopback.
// The browser never sees the client cert; admin-ui acts as the mTLS
// client and re-streams the bytes 1:1 (with per-event flushing).
type auditHandler struct {
	get func() (*proxyClient, error)
}

// logStat proxies GET /admin/log/stat — current audit log size + mtime.
func (h *auditHandler) logStat(w http.ResponseWriter, r *http.Request) {
	h.passthrough(w, r, "GET", "/admin/log/stat")
}

// logRotate proxies POST /admin/log/rotate — forces a rename+reopen
// of the audit log on the proxy and returns the rotated-to path.
func (h *auditHandler) logRotate(w http.ResponseWriter, r *http.Request) {
	h.passthrough(w, r, "POST", "/admin/log/rotate")
}

// health proxies GET /admin/healthz — used by the UI badge to poll
// proxy liveness every 5 s.
func (h *auditHandler) health(w http.ResponseWriter, r *http.Request) {
	h.passthrough(w, r, "GET", "/admin/healthz")
}

// passthrough is the generic mTLS proxy for short JSON admin calls.
// Streams body 1:1; mirrors content-type and status. Unsuitable for
// SSE — use the dedicated tail handler instead.
func (h *auditHandler) passthrough(w http.ResponseWriter, r *http.Request, method, path string) {
	pc, err := h.get()
	if err != nil {
		writeErr(w, http.StatusFailedDependency, err.Error())
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), method, pc.url(path), nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp, err := pc.hc.Do(req)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "upstream: "+err.Error())
		return
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// rangeHist proxies GET /admin/audit/range — JSON-lines history scan
// over the on-disk log. Query params (lines / since / until) pass
// through unchanged.
func (h *auditHandler) rangeHist(w http.ResponseWriter, r *http.Request) {
	pc, err := h.get()
	if err != nil {
		writeErr(w, http.StatusFailedDependency, err.Error())
		return
	}
	upstream := pc.url("/admin/audit/range")
	if q := r.URL.RawQuery; q != "" {
		upstream += "?" + q
	}
	req, err := http.NewRequestWithContext(r.Context(), "GET", upstream, nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp, err := pc.hc.Do(req)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "upstream: "+err.Error())
		return
	}
	defer resp.Body.Close()
	// Mirror upstream content-type/status; body is bounded by the
	// 10k-line cap on the proxy, so io.Copy is fine.
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (h *auditHandler) tail(w http.ResponseWriter, r *http.Request) {
	pc, err := h.get()
	if err != nil {
		writeErr(w, http.StatusFailedDependency, err.Error())
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	// New request with browser ctx so cancellation propagates upstream.
	req, err := http.NewRequestWithContext(r.Context(), "GET", pc.url("/admin/audit/tail"), nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if last := r.Header.Get("Last-Event-ID"); last != "" {
		req.Header.Set("Last-Event-ID", last)
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := pc.hc.Do(req)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "upstream: "+err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Mirror upstream non-200 (most likely 403 if the client cert
		// lacks the admin role) so the browser can show the operator
		// the actual reason instead of a generic gateway error.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, `{"error":"upstream status %d"}`, resp.StatusCode)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Stream upstream → browser. Flush after each chunk so EventSource
	// dispatches events promptly; SSE event boundaries are `\n\n` and
	// upstream already flushes per event, so reads land on boundaries.
	if err := pumpFlushing(r.Context(), w, flusher, resp.Body); err != nil {
		// Stream already started — nothing useful to do with the error
		// besides letting the connection close.
		_ = err
	}
}

func pumpFlushing(ctx context.Context, w io.Writer, flusher http.Flusher, r io.Reader) error {
	buf := make([]byte, 4096)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, err := r.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return werr
			}
			flusher.Flush()
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}
