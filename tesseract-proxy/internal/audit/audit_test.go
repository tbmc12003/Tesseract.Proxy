package audit_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/equinomics/tesseract-proxy/internal/audit"
)

func openWriter(t *testing.T, ringSize int) (*audit.Writer, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "audit.log")
	w, err := audit.Open(audit.Options{Path: p, RingSize: ringSize})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w, p
}

func readLines(t *testing.T, path string) []audit.Record {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []audit.Record
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r audit.Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("bad json line %q: %v", sc.Text(), err)
		}
		out = append(out, r)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestOpen_RequiresPath(t *testing.T) {
	t.Parallel()
	if _, err := audit.Open(audit.Options{}); err == nil {
		t.Error("expected error for empty path")
	}
}

func TestLog_WritesJSONLines(t *testing.T) {
	t.Parallel()
	w, path := openWriter(t, 16)
	for i := 0; i < 3; i++ {
		err := w.Log(audit.Record{
			Outcome:   audit.OutcomeForward,
			Method:    "POST",
			Path:      "/Orders/2.0/quick/order/cancel",
			Status:    200,
			LatencyMs: int64(10 + i),
			BrokerID:  "papertrader",
			Serial:    "1001",
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	got := readLines(t, path)
	if len(got) != 3 {
		t.Fatalf("got %d records, want 3", len(got))
	}
	if got[0].Outcome != audit.OutcomeForward || got[2].LatencyMs != 12 {
		t.Errorf("records mismatch: %+v", got)
	}
}

func TestLog_NoBodyFields(t *testing.T) {
	t.Parallel()
	// Compile-time evidence: the Record struct has no body fields.
	// Runtime evidence: a serialised record never carries a "body" key.
	w, path := openWriter(t, 4)
	if err := w.Log(audit.Record{
		Outcome:   audit.OutcomeForward,
		Method:    "POST",
		Path:      "/x",
		Status:    200,
		BrokerID:  "papertrader",
		LatencyMs: 1,
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) == "" {
		t.Fatal("no log line written")
	}
	var generic map[string]any
	if err := json.Unmarshal(raw[:len(raw)-1], &generic); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"body", "request_body", "response_body"} {
		if _, present := generic[forbidden]; present {
			t.Errorf("forbidden field %q present in audit record", forbidden)
		}
	}
}

func TestRecent_ReturnsLastN(t *testing.T) {
	t.Parallel()
	w, _ := openWriter(t, 4)
	for i := 0; i < 6; i++ {
		_ = w.Log(audit.Record{
			Outcome:   audit.OutcomeForward,
			Method:    "POST",
			Path:      "/x",
			Status:    200,
			LatencyMs: int64(i),
		})
	}
	got := w.Recent(10) // request more than the ring size
	if len(got) != 4 {
		t.Fatalf("Recent(10) returned %d, want 4 (ring cap)", len(got))
	}
	// Ring should hold the last 4 (latencies 2..5) in chronological order.
	wantLatencies := []int64{2, 3, 4, 5}
	for i, r := range got {
		if r.LatencyMs != wantLatencies[i] {
			t.Errorf("Recent[%d].LatencyMs = %d, want %d", i, r.LatencyMs, wantLatencies[i])
		}
	}
}

func TestRecent_PartialFill(t *testing.T) {
	t.Parallel()
	w, _ := openWriter(t, 8)
	for i := 0; i < 3; i++ {
		_ = w.Log(audit.Record{
			Outcome:   audit.OutcomeForward,
			Method:    "POST",
			Path:      "/x",
			LatencyMs: int64(i),
		})
	}
	if got := w.Recent(100); len(got) != 3 {
		t.Errorf("Recent on partially-filled ring = %d, want 3", len(got))
	}
	if got := w.Recent(2); len(got) != 2 || got[0].LatencyMs != 1 || got[1].LatencyMs != 2 {
		t.Errorf("Recent(2) chronological tail wrong: %+v", got)
	}
}

func TestRecent_EmptyReturnsNil(t *testing.T) {
	t.Parallel()
	w, _ := openWriter(t, 4)
	if got := w.Recent(5); got != nil {
		t.Errorf("Recent on empty writer = %+v, want nil", got)
	}
}

func TestReopen_SwitchesFileHandle(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		// Windows holds an exclusive lock on the open file, so the
		// logrotate-style rename-then-reopen flow this test simulates
		// is not representative of the deployment target (linux/arm64
		// on Lightsail). CI exercises this on Linux.
		t.Skip("Windows cannot rename open files; logrotate-style flow only meaningful on Linux")
	}
	w, path := openWriter(t, 4)
	_ = w.Log(audit.Record{Outcome: audit.OutcomeForward, Method: "POST", Path: "/a", Status: 200})

	// Simulate logrotate: rename the current file out of the way.
	rotated := path + ".1"
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if err := w.Reopen(); err != nil {
		t.Fatalf("Reopen: %v", err)
	}
	_ = w.Log(audit.Record{Outcome: audit.OutcomeForward, Method: "POST", Path: "/b", Status: 200})

	pre := readLines(t, rotated)
	post := readLines(t, path)
	if len(pre) != 1 || pre[0].Path != "/a" {
		t.Errorf("rotated file content: %+v", pre)
	}
	if len(post) != 1 || post[0].Path != "/b" {
		t.Errorf("new file content: %+v", post)
	}
}

func TestClose_LogAfterCloseErrors(t *testing.T) {
	t.Parallel()
	w, _ := openWriter(t, 4)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Log(audit.Record{Outcome: audit.OutcomeForward, Method: "POST", Path: "/x"}); err == nil {
		t.Error("Log after Close should error")
	}
}

func TestLog_FillsTimeWhenZero(t *testing.T) {
	t.Parallel()
	w, path := openWriter(t, 4)
	before := time.Now().Add(-time.Second)
	_ = w.Log(audit.Record{Outcome: audit.OutcomeForward, Method: "POST", Path: "/x", Status: 200})
	got := readLines(t, path)
	if got[0].Time.Before(before) {
		t.Errorf("auto-stamped Time looks wrong: %v", got[0].Time)
	}
}

func TestLog_Concurrent(t *testing.T) {
	t.Parallel()
	w, path := openWriter(t, 256)
	var wg sync.WaitGroup
	const writers = 8
	const each = 50
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				_ = w.Log(audit.Record{
					Outcome: audit.OutcomeForward,
					Method:  "POST",
					Path:    "/x",
					Status:  200,
				})
			}
		}()
	}
	wg.Wait()
	got := readLines(t, path)
	if len(got) != writers*each {
		t.Errorf("got %d lines, want %d (no torn writes)", len(got), writers*each)
	}
}

func TestSubscribe_LiveDelivery(t *testing.T) {
	w, _ := openWriter(t, 16)
	sub := w.Subscribe(8, time.Time{})
	defer sub.Close()
	if len(sub.Backlog) != 0 {
		t.Fatalf("expected empty backlog on fresh writer, got %d", len(sub.Backlog))
	}

	rec := audit.Record{Outcome: audit.OutcomeForward, Method: "POST", Path: "/x", Status: 200}
	if err := w.Log(rec); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-sub.Ch:
		if got.Path != "/x" {
			t.Errorf("got path %q, want /x", got.Path)
		}
	case <-time.After(time.Second):
		t.Fatal("no record delivered to live subscriber")
	}
}

func TestSubscribe_BacklogAfterFilter(t *testing.T) {
	w, _ := openWriter(t, 16)
	// Three records with explicit, monotonically increasing timestamps.
	base := time.Now()
	for i := 0; i < 3; i++ {
		if err := w.Log(audit.Record{
			Time:    base.Add(time.Duration(i) * time.Second),
			Method:  "GET",
			Path:    "/p",
			Status:  200,
			Outcome: audit.OutcomeForward,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// after = base + 0.5s → expect records at +1s and +2s only.
	sub := w.Subscribe(0, base.Add(500*time.Millisecond))
	defer sub.Close()
	if len(sub.Backlog) != 2 {
		t.Fatalf("backlog len = %d, want 2 (after-filter)", len(sub.Backlog))
	}
	if !sub.Backlog[0].Time.Equal(base.Add(time.Second)) {
		t.Errorf("backlog[0].Time = %v, want %v", sub.Backlog[0].Time, base.Add(time.Second))
	}
}

func TestSubscribe_DroppedWhenChannelFull(t *testing.T) {
	w, _ := openWriter(t, 16)
	sub := w.Subscribe(2, time.Time{}) // tiny buffer to force drops
	defer sub.Close()
	for i := 0; i < 5; i++ {
		if err := w.Log(audit.Record{Method: "GET", Path: "/p", Status: 200, Outcome: audit.OutcomeForward}); err != nil {
			t.Fatal(err)
		}
	}
	if got := sub.DroppedAndReset(); got != 3 {
		t.Errorf("dropped = %d, want 3 (buffer=2, sent=5)", got)
	}
	if got := sub.DroppedAndReset(); got != 0 {
		t.Errorf("dropped after reset = %d, want 0", got)
	}
}

func TestSubscribe_CloseStopsDelivery(t *testing.T) {
	w, _ := openWriter(t, 16)
	sub := w.Subscribe(4, time.Time{})
	sub.Close()
	// After Close, a subsequent Log must not deliver to the (now-detached)
	// channel — i.e. drained Ch should not gain new records.
	for i := 0; i < 3; i++ {
		_ = w.Log(audit.Record{Method: "GET", Path: "/p", Status: 200, Outcome: audit.OutcomeForward})
	}
	// Drain anything that was sent in the race window; then confirm idle.
	for {
		select {
		case <-sub.Ch:
		case <-time.After(50 * time.Millisecond):
			goto done
		}
	}
done:
	// Log one more; should not appear.
	_ = w.Log(audit.Record{Method: "GET", Path: "/late", Status: 200, Outcome: audit.OutcomeForward})
	select {
	case got := <-sub.Ch:
		t.Fatalf("unexpected delivery after Close: %+v", got)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestRotate_RenamesAndReopens(t *testing.T) {
	w, p := openWriter(t, 16)
	if err := w.Log(audit.Record{Method: "POST", Path: "/before"}); err != nil {
		t.Fatal(err)
	}
	rotated, err := w.Rotate()
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if _, err := os.Stat(rotated); err != nil {
		t.Fatalf("rotated file missing: %v", err)
	}
	// New file at original path should exist and be empty.
	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("new audit.log missing: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("new file size = %d, want 0", info.Size())
	}
	// Writer should keep working.
	if err := w.Log(audit.Record{Method: "POST", Path: "/after"}); err != nil {
		t.Fatalf("Log after rotate: %v", err)
	}
	// rotated file should contain "before", current file should contain "after".
	before := readLines(t, rotated)
	if len(before) != 1 || before[0].Path != "/before" {
		t.Errorf("rotated contents: %+v", before)
	}
	after := readLines(t, p)
	if len(after) != 1 || after[0].Path != "/after" {
		t.Errorf("post-rotate contents: %+v", after)
	}
}

func TestStat_ReportsSize(t *testing.T) {
	w, _ := openWriter(t, 16)
	_ = w.Log(audit.Record{Method: "POST", Path: "/x"})
	size, mtime, err := w.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if size == 0 {
		t.Errorf("size = 0, want > 0 after one Log")
	}
	if mtime.IsZero() {
		t.Errorf("mtime is zero")
	}
}
