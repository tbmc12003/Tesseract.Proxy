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

	subs []*subscription
}

// subscription is the internal representation of a live tail subscriber.
type subscription struct {
	ch      chan Record
	dropped int64 // accessed under Writer.mu only
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
	// Live tail fan-out. Non-blocking — a slow subscriber accumulates a
	// drop count rather than back-pressuring the order plane. The SSE
	// handler surfaces the drop count to the client as a sentinel event
	// before the next real record.
	for _, sub := range w.subs {
		select {
		case sub.ch <- r:
		default:
			sub.dropped++
		}
	}
	return nil
}

// Subscription is what Subscribe returns to a caller (the SSE handler in
// internal/admin). The caller drains Ch, periodically reads DroppedAndReset
// to surface flow-control gaps, and calls Close when the HTTP request ends.
type Subscription struct {
	// Backlog contains records from the in-memory ring that are strictly
	// newer than the `after` timestamp passed to Subscribe. The handler
	// should emit these before reading from Ch so SSE reconnects with a
	// Last-Event-ID get a contiguous stream (bounded by ring size).
	Backlog []Record
	// Ch is the live stream. Records sent after Subscribe returned.
	Ch <-chan Record
	// DroppedAndReset returns the count of records dropped due to a
	// full Ch since the last call, and resets the counter to zero.
	DroppedAndReset func() int64
	// Close removes the subscription from the writer. Must be called
	// exactly once.
	Close func()
}

// Subscribe registers a new live tail subscriber. bufSize is the channel
// capacity (a sensible default is the ring size). `after` filters the
// ring backlog: only records with Time strictly greater than `after` are
// returned. Pass a zero time.Time for no backlog.
func (w *Writer) Subscribe(bufSize int, after time.Time) *Subscription {
	if bufSize <= 0 {
		bufSize = w.ringSize
	}
	sub := &subscription{ch: make(chan Record, bufSize)}

	w.mu.Lock()
	// Build backlog from the ring, oldest-first, only records strictly
	// after `after`.
	have := w.head
	if w.full {
		have = w.ringSize
	}
	var backlog []Record
	if have > 0 {
		start := (w.head - have + w.ringSize) % w.ringSize
		for i := 0; i < have; i++ {
			rec := w.ring[(start+i)%w.ringSize]
			if !after.IsZero() && !rec.Time.After(after) {
				continue
			}
			backlog = append(backlog, rec)
		}
	}
	w.subs = append(w.subs, sub)
	w.mu.Unlock()

	return &Subscription{
		Backlog: backlog,
		Ch:      sub.ch,
		DroppedAndReset: func() int64 {
			w.mu.Lock()
			n := sub.dropped
			sub.dropped = 0
			w.mu.Unlock()
			return n
		},
		Close: func() {
			w.mu.Lock()
			for i, s := range w.subs {
				if s == sub {
					w.subs = append(w.subs[:i], w.subs[i+1:]...)
					break
				}
			}
			w.mu.Unlock()
			// Drain — let any in-flight sender complete (lock already
			// dropped, so a concurrent Log might still race in. Closing
			// the channel is unsafe under that race; rely on GC instead.)
		},
	}
}

// Path returns the on-disk audit log path. Used by /admin/audit/range
// to scan history beyond the in-memory ring.
func (w *Writer) Path() string { return w.path }

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

// Rotate renames the current audit log to `<path>.<UTC timestamp>` and
// reopens a fresh file at the original path. Atomic w.r.t. concurrent
// Log calls — both hold w.mu. Returns the rotated-to path so callers
// can surface it to the operator. If the rename fails, the original
// handle is reopened so the writer stays usable.
func (w *Writer) Rotate() (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return "", errors.New("audit: writer is closed")
	}
	if err := w.f.Close(); err != nil {
		// Best-effort: try to reopen so the writer isn't dead.
		_ = w.openFile()
		return "", fmt.Errorf("close current: %w", err)
	}
	w.f = nil
	w.enc = nil
	rotated := w.path + "." + time.Now().UTC().Format("20060102T150405Z")
	if err := os.Rename(w.path, rotated); err != nil {
		// If rename failed (e.g. permission), re-open the original so
		// the writer keeps working — better partial recovery than a
		// dead audit logger.
		if reErr := w.openFile(); reErr != nil {
			return "", fmt.Errorf("rename %s -> %s: %w (and reopen failed: %v)",
				w.path, rotated, err, reErr)
		}
		return "", fmt.Errorf("rename %s -> %s: %w", w.path, rotated, err)
	}
	if err := w.openFile(); err != nil {
		return rotated, fmt.Errorf("reopen after rotate: %w", err)
	}
	return rotated, nil
}

// Stat returns size + mtime metadata for the current audit log. Safe
// to call concurrently with Log.
func (w *Writer) Stat() (size int64, modTime time.Time, err error) {
	info, err := os.Stat(w.path)
	if err != nil {
		return 0, time.Time{}, err
	}
	return info.Size(), info.ModTime(), nil
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
