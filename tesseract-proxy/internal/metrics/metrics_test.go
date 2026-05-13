package metrics_test

import (
	"strings"
	"sync"
	"testing"

	"github.com/equinomics/tesseract-proxy/internal/audit"
	"github.com/equinomics/tesseract-proxy/internal/metrics"
)

func TestIncOutcome_ScalarBumps(t *testing.T) {
	t.Parallel()
	c := &metrics.Counters{}
	c.IncOutcome(audit.OutcomeForward)
	c.IncOutcome(audit.OutcomeForward)
	c.IncOutcome(audit.OutcomeReject)
	c.IncOutcome(audit.OutcomeUpstreamErr)
	if got := c.Forwards.Load(); got != 2 {
		t.Errorf("Forwards = %d, want 2", got)
	}
	if got := c.Rejects.Load(); got != 1 {
		t.Errorf("Rejects = %d, want 1", got)
	}
	if got := c.UpstreamErrors.Load(); got != 1 {
		t.Errorf("UpstreamErrors = %d, want 1", got)
	}
}

func TestLabeledCounter_IncAndSnapshot(t *testing.T) {
	t.Parallel()
	var c metrics.LabeledCounter
	c.Inc("kotakneo")
	c.Inc("kotakneo")
	c.Inc("fyers")
	snap := c.Snapshot()
	if snap["kotakneo"] != 2 || snap["fyers"] != 1 {
		t.Errorf("snapshot = %+v", snap)
	}
	// Snapshot is a copy: mutating it doesn't affect the counter.
	snap["kotakneo"] = 999
	if c.Snapshot()["kotakneo"] != 2 {
		t.Error("Snapshot did not return a copy")
	}
}

func TestLabeledCounter_Concurrent(t *testing.T) {
	t.Parallel()
	var c metrics.LabeledCounter
	var wg sync.WaitGroup
	const writers, each = 8, 250
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				c.Inc("a")
			}
		}()
	}
	wg.Wait()
	if got := c.Snapshot()["a"]; got != writers*each {
		t.Errorf("concurrent Inc = %d, want %d", got, writers*each)
	}
}

func TestRender_ContainsAllSeries(t *testing.T) {
	t.Parallel()
	c := &metrics.Counters{}
	c.Forwards.Store(42)
	c.HandshakeFailures.Inc("unknown_serial")
	c.HandshakeFailures.Inc("unknown_serial")
	c.HandshakeFailures.Inc("expired")
	c.BrokerAuthFailures.Inc("kotakneo")

	out := c.Render()
	for _, want := range []string{
		"# TYPE tesseract_forwards_total counter",
		"tesseract_forwards_total 42",
		"# TYPE tesseract_mtls_handshake_failures_total counter",
		`tesseract_mtls_handshake_failures_total{reason="unknown_serial"} 2`,
		`tesseract_mtls_handshake_failures_total{reason="expired"} 1`,
		"# TYPE tesseract_broker_auth_failures_total counter",
		`tesseract_broker_auth_failures_total{broker_id="kotakneo"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n--- out ---\n%s", want, out)
		}
	}
}

func TestRender_EmptyLabeledEmitsZeroSample(t *testing.T) {
	t.Parallel()
	c := &metrics.Counters{}
	out := c.Render()
	// Empty labeled series still surface as a TYPE + 0 sample so the
	// metric exists in Prometheus from the first scrape.
	if !strings.Contains(out, `tesseract_mtls_handshake_failures_total{reason=""} 0`) {
		t.Errorf("empty handshake labeled missing zero sample:\n%s", out)
	}
	if !strings.Contains(out, `tesseract_broker_auth_failures_total{broker_id=""} 0`) {
		t.Errorf("empty broker-auth labeled missing zero sample:\n%s", out)
	}
}

func TestRender_LabeledSampleOrderIsStable(t *testing.T) {
	t.Parallel()
	c := &metrics.Counters{}
	c.HandshakeFailures.Inc("zebra")
	c.HandshakeFailures.Inc("alpha")
	c.HandshakeFailures.Inc("mike")
	out := c.Render()
	// Lines sorted lexicographically.
	aIdx := strings.Index(out, `reason="alpha"`)
	mIdx := strings.Index(out, `reason="mike"`)
	zIdx := strings.Index(out, `reason="zebra"`)
	if !(aIdx < mIdx && mIdx < zIdx) {
		t.Errorf("labels not sorted: alpha@%d mike@%d zebra@%d", aIdx, mIdx, zIdx)
	}
}
