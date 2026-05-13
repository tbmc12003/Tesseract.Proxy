package profile

import "sync/atomic"

// Holder is a concurrent-safe slot for the live Router. It uses
// atomic.Pointer so hot-path Lookups are lock-free and reload-time swaps
// don't block in-flight reads.
//
// Reload semantics (arch §13.5): a swap publishes a fully-built new Router.
// In-flight requests that have already loaded the old pointer continue to
// route against it; subsequent loads pick up the new pointer. The old
// Router is retained by callers that loaded it earlier and is eligible for
// GC once their references drop.
//
// Note: this type only owns the route table. Connection pools to broker
// hosts (which must persist across swaps when the host is unchanged) are
// owned by the reverse-proxy layer (P2.6) and keyed by host, not by
// Router pointer.
type Holder struct {
	p atomic.Pointer[Router]
}

// NewHolder constructs a Holder pre-loaded with r. r may be nil for a
// "no bundle loaded yet" state; callers must handle a nil Load() result.
func NewHolder(r *Router) *Holder {
	h := &Holder{}
	h.p.Store(r)
	return h
}

// Load returns the currently active Router, or nil if none has been loaded
// yet. This is the hot-path call used per request.
func (h *Holder) Load() *Router { return h.p.Load() }

// Store atomically publishes r as the new active Router. The previous
// Router (if any) is returned for the caller's bookkeeping (audit log of
// old→new bundle_version, retention as `bundle.yaml.previous`, etc.).
func (h *Holder) Store(r *Router) *Router {
	prev := h.p.Swap(r)
	return prev
}
