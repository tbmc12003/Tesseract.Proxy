// Package audit writes the proxy's per-request audit log (arch §7, §7.0).
//
// On-disk format is JSON-lines: one record per call to Log, separated by
// '\n'. Records carry metadata only — timestamp, cert serial, broker id,
// method, path, status, latency, idempotency key, bundle version — and
// explicitly never bodies. Rotation is performed out-of-process by
// `logrotate(8)`; on SIGHUP the operator calls Reopen to swap to a fresh
// file handle at the same path (supporting `logrotate`'s `create` mode).
//
// A bounded ring buffer of the most recent N records is retained in memory
// so the admin endpoint `/admin/audit/recent?n=…` can serve the recent
// tail without re-reading the on-disk log.
package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// Outcome categorises an audit record.
type Outcome string

const (
	OutcomeForward     Outcome = "forward"      // request proxied to broker; broker responded
	OutcomeReject      Outcome = "reject"       // 4xx from this hop (missing header, allowlist miss)
	OutcomeUpstreamErr Outcome = "upstream_err" // 5xx from this hop (broker dial/RT failure)
)

// Record is a single audit-log entry. Field tags use snake_case to match
// arch §7.0; omitempty omits empty strings so reject/replay records stay
// compact.
type Record struct {
	Time           time.Time `json:"time"`
	Outcome        Outcome   `json:"outcome"`
	Serial         string    `json:"cert_serial,omitempty"`
	BrokerID       string    `json:"broker_id,omitempty"`
	Method         string    `json:"method"`
	Path           string    `json:"path"`
	Status         int       `json:"status"`
	LatencyMs      int64     `json:"latency_ms"`
	IdempotencyKey string    `json:"idempotency_key,omitempty"`
	BundleVersion  string    `json:"bundle_version,omitempty"`
	Reason         string    `json:"reason,omitempty"`
}

// Writer is the file-backed audit-log writer with an in-memory ring of
// recent records. All public methods are concurrent-safe.
type Writer struct {
	path     string
	ringSize int

	mu   sync.Mutex
	f    *os.File
	enc  *json.Encoder
	ring []Record
	head int // index where the next record will be written
	full bool
}

// Options configures a Writer.
type Options struct {
	// Path is the audit log file. The file is opened with O_APPEND so
	// concurrent writers (e.g. an out-of-process logrotate-friendly
	// helper) do not interleave records mid-line.
	Path string
	// RingSize is the number of most-recent records retained in memory
	// for /admin/audit/recent. 256 is a sensible default; the value
	// comes from operator config in production wiring.
	RingSize int
}

// Open creates or opens the audit log file and returns a Writer.
func Open(opts Options) (*Writer, error) {
	if opts.Path == "" {
		return nil, errors.New("audit: Path is required")
	}
	if opts.RingSize <= 0 {
		opts.RingSize = 256
	}
	w := &Writer{
		path:     opts.Path,
		ringSize: opts.RingSize,
		ring:     make([]Record, opts.RingSize),
	}
	if err := w.openFile(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Writer) openFile() error {
	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("audit: open %s: %w", w.path, err)
	}
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	w.f = f
	w.enc = enc
	return nil
}

// Log appends a single record. The record's Time is set to time.Now() if
// the caller left it zero, so call sites don't have to remember.
func (w *Writer) Log(r Record) error {
	if r.Time.IsZero() {
		r.Time = time.Now()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return errors.New("audit: writer is closed")
	}
	if err := w.enc.Encode(r); err != nil {
		return fmt.Errorf("audit: write: %w", err)
	}
	// Ring update.
	w.ring[w.head] = r
	w.head = (w.head + 1) % w.ringSize
	if w.head == 0 {
		w.full = true
	}
	return nil
}

// Recent returns up to n most-recent records in chronological order
// (oldest of the requested window first, newest last).
func (w *Writer) Recent(n int) []Record {
	w.mu.Lock()
	defer w.mu.Unlock()
	have := w.head
	if w.full {
		have = w.ringSize
	}
	if n > have {
		n = have
	}
	if n <= 0 {
		return nil
	}
	out := make([]Record, n)
	// Records are stored at positions [start, start+1, ... head-1] mod ringSize.
	start := (w.head - n + w.ringSize) % w.ringSize
	for i := 0; i < n; i++ {
		out[i] = w.ring[(start+i)%w.ringSize]
	}
	return out
}

// Reopen closes the current file handle and reopens the configured path.
// Used after `logrotate` has rotated the file out from under us.
func (w *Writer) Reopen() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f != nil {
		_ = w.f.Close()
		w.f = nil
		w.enc = nil
	}
	return w.openFile()
}

// Close releases the file handle. Further Log calls return an error.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	w.enc = nil
	return err
}
