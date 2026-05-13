// Package metrics owns the proxy's runtime counters. The proxy hot path
// calls IncOutcome to record what happened to each request; the admin
// endpoint /admin/metrics calls Render to expose the counters in
// Prometheus text-exposition format.
//
// Counters are atomic — no mutex on the hot path.
package metrics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/equinomics/tesseract-proxy/internal/audit"
)

// LabeledCounter is a small label-aware counter. Each Inc call bumps the
// bucket for the given label value; Snapshot returns a deep copy. Lazy
// map init means a zero-value LabeledCounter is usable directly — handy
// because Counters is constructed via composite literal `&Counters{}` in
// most call sites.
type LabeledCounter struct {
	mu   sync.Mutex
	vals map[string]int64
}

// Inc bumps the bucket for label by 1.
func (c *LabeledCounter) Inc(label string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.vals == nil {
		c.vals = make(map[string]int64)
	}
	c.vals[label]++
}

// Snapshot returns a copy of the current counter values keyed by label.
func (c *LabeledCounter) Snapshot() map[string]int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]int64, len(c.vals))
	for k, v := range c.vals {
		out[k] = v
	}
	return out
}

// Counters is the aggregate counter set. Plain atomic.Int64 fields cover
// the outcome distribution; LabeledCounter fields carry one dimension
// each (reason for handshake failures, broker_id for broker-auth
// failures — P2.16).
type Counters struct {
	Forwards       atomic.Int64
	Rejects        atomic.Int64
	UpstreamErrors atomic.Int64

	HandshakeFailures  LabeledCounter // reason="unknown_serial|no_client_cert|wrong_ca|expired|tls_version|other"
	BrokerAuthFailures LabeledCounter // broker_id="<id>" — observation, not enforcement
}

// IncOutcome bumps the counter matching o.
func (c *Counters) IncOutcome(o audit.Outcome) {
	switch o {
	case audit.OutcomeForward:
		c.Forwards.Add(1)
	case audit.OutcomeReject:
		c.Rejects.Add(1)
	case audit.OutcomeUpstreamErr:
		c.UpstreamErrors.Add(1)
	}
}

// Render produces Prometheus text exposition (version 0.0.4). Each
// counter emits one TYPE comment and one (or more, for labeled
// counters) sample lines. Names are prefixed with `tesseract_` so
// scrape collisions with other targets are avoided.
func (c *Counters) Render() string {
	var sb strings.Builder
	emit := func(name string, val int64) {
		fmt.Fprintf(&sb, "# TYPE tesseract_%s counter\n", name)
		fmt.Fprintf(&sb, "tesseract_%s %d\n", name, val)
	}
	emit("forwards_total", c.Forwards.Load())
	emit("rejects_total", c.Rejects.Load())
	emit("upstream_errors_total", c.UpstreamErrors.Load())
	emitLabeled(&sb, "mtls_handshake_failures_total", "reason", c.HandshakeFailures.Snapshot())
	emitLabeled(&sb, "broker_auth_failures_total", "broker_id", c.BrokerAuthFailures.Snapshot())
	return sb.String()
}

func emitLabeled(sb *strings.Builder, name, label string, vals map[string]int64) {
	fmt.Fprintf(sb, "# TYPE tesseract_%s counter\n", name)
	if len(vals) == 0 {
		// Emit a zero sample with an empty label so the metric is
		// discoverable in `/admin/metrics` from scrape #1 even before
		// any event has fired. Prometheus accepts an empty label value.
		fmt.Fprintf(sb, "tesseract_%s{%s=\"\"} 0\n", name, label)
		return
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(sb, "tesseract_%s{%s=%q} %d\n", name, label, k, vals[k])
	}
}
