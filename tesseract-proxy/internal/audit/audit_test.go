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
