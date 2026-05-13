package egress_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/equinomics/tesseract-proxy/internal/egress"
)

type stubResolver struct {
	table map[string][]net.IP
	mu    sync.Mutex
	calls atomic.Int64
}

func (s *stubResolver) LookupHost(_ context.Context, host string) ([]net.IP, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls.Add(1)
	ips, ok := s.table[host]
	if !ok {
		return nil, fmt.Errorf("stub: no resolution for %s", host)
	}
	if len(ips) == 0 {
		return nil, errors.New("stub: empty result")
	}
	return ips, nil
}

type stubApplier struct {
	mu        sync.Mutex
	last      string
	calls     atomic.Int64
	failNext  bool
}

func (s *stubApplier) Apply(_ context.Context, ruleset string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls.Add(1)
	if s.failNext {
		s.failNext = false
		return errors.New("stub: forced apply failure")
	}
	s.last = ruleset
	return nil
}

func (s *stubApplier) Last() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

func newGen(t *testing.T, res *stubResolver, app *stubApplier, interval time.Duration) *egress.Generator {
	t.Helper()
	g, err := egress.New(egress.Options{
		Resolver: res,
		Applier:  app,
		Interval: interval,
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestRender_BasicShape(t *testing.T) {
	t.Parallel()
	out := egress.Render(
		[]string{"a.example.com", "b.example.com"},
		[]net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("2001:db8::1"), net.ParseIP("5.6.7.8")},
	)
	for _, want := range []string{
		"table inet tesseract_egress",
		"policy drop;",
		"ct state established,related accept",
		"oif lo accept",
		"tcp dport 443 ip daddr { 1.2.3.4, 5.6.7.8 } accept",
		"tcp dport 443 ip6 daddr { 2001:db8::1 } accept",
		"#   a.example.com",
		"#   b.example.com",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ruleset missing %q\n--- out ---\n%s", want, out)
		}
	}
}

func TestRender_Deterministic(t *testing.T) {
	t.Parallel()
	hosts := []string{"a", "b"}
	ips := []net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("5.6.7.8")}
	first := egress.Render(hosts, ips)
	second := egress.Render(hosts, ips)
	if first != second {
		t.Error("Render not deterministic")
	}
}

func TestResolveAll_Success(t *testing.T) {
	t.Parallel()
	res := &stubResolver{table: map[string][]net.IP{
		"a": {net.ParseIP("1.2.3.4")},
		"b": {net.ParseIP("5.6.7.8"), net.ParseIP("1.2.3.4")}, // dup with a
	}}
	got, err := egress.ResolveAll(context.Background(), res, []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("got %d IPs, want 2 (deduped)", len(got))
	}
}

func TestResolveAll_FailureSurfacedAndAtomic(t *testing.T) {
	t.Parallel()
	res := &stubResolver{table: map[string][]net.IP{
		"good": {net.ParseIP("1.2.3.4")},
		// "bad" missing — will error
	}}
	_, err := egress.ResolveAll(context.Background(), res, []string{"good", "bad"})
	if err == nil || !strings.Contains(err.Error(), "bad") {
		t.Errorf("expected error mentioning bad host, got %v", err)
	}
}

func TestTick_NoHostsIsNoOp(t *testing.T) {
	t.Parallel()
	res := &stubResolver{}
	app := &stubApplier{}
	g := newGen(t, res, app, time.Hour)
	if err := g.Tick(context.Background()); err != nil {
		t.Errorf("Tick with no hosts errored: %v", err)
	}
	if app.calls.Load() != 0 {
		t.Errorf("apply called %d times with no hosts (want 0)", app.calls.Load())
	}
}

func TestTick_AppliesRuleset(t *testing.T) {
	t.Parallel()
	res := &stubResolver{table: map[string][]net.IP{
		"papertrader.local": {net.ParseIP("127.0.0.1")},
	}}
	app := &stubApplier{}
	g := newGen(t, res, app, time.Hour)
	g.UpdateHosts([]string{"papertrader.local"})
	if err := g.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(app.Last(), "127.0.0.1") {
		t.Errorf("applied ruleset missing resolved IP: %q", app.Last())
	}
}

func TestTick_PartialResolveFailureSkipsApply(t *testing.T) {
	t.Parallel()
	res := &stubResolver{table: map[string][]net.IP{
		"good": {net.ParseIP("1.2.3.4")},
	}}
	app := &stubApplier{}
	g := newGen(t, res, app, time.Hour)
	g.UpdateHosts([]string{"good", "bad"})
	if err := g.Tick(context.Background()); err == nil {
		t.Error("expected error when a host doesn't resolve")
	}
	if app.calls.Load() != 0 {
		t.Errorf("apply should not have been called; got %d", app.calls.Load())
	}
}

func TestUpdateHosts_DedupesAndSorts(t *testing.T) {
	t.Parallel()
	res := &stubResolver{table: map[string][]net.IP{
		"a.example.com": {net.ParseIP("1.1.1.1")},
		"b.example.com": {net.ParseIP("2.2.2.2")},
	}}
	app := &stubApplier{}
	g := newGen(t, res, app, time.Hour)
	g.UpdateHosts([]string{"b.example.com", "a.example.com", "a.example.com"})
	if err := g.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	rs := app.Last()
	// Hosts comment list should be sorted a, then b.
	if a := strings.Index(rs, "a.example.com"); a < 0 || a > strings.Index(rs, "b.example.com") {
		t.Errorf("hosts not sorted: %q", rs)
	}
}

func TestRun_PokeAndTickerBothFire(t *testing.T) {
	t.Parallel()
	res := &stubResolver{table: map[string][]net.IP{
		"a": {net.ParseIP("1.2.3.4")},
	}}
	app := &stubApplier{}
	g := newGen(t, res, app, 50*time.Millisecond)
	g.UpdateHosts([]string{"a"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- g.Run(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && app.calls.Load() < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	if app.calls.Load() < 2 {
		t.Errorf("expected at least 2 apply calls (poke + tick), got %d", app.calls.Load())
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run returned %v", err)
	}
}

func TestRun_ApplyErrorDoesNotKillLoop(t *testing.T) {
	t.Parallel()
	res := &stubResolver{table: map[string][]net.IP{
		"a": {net.ParseIP("1.2.3.4")},
	}}
	app := &stubApplier{failNext: true}
	g := newGen(t, res, app, 30*time.Millisecond)
	g.UpdateHosts([]string{"a"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- g.Run(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && app.calls.Load() < 3 {
		time.Sleep(20 * time.Millisecond)
	}
	if app.calls.Load() < 3 {
		t.Errorf("loop appears stuck after apply error; calls=%d", app.calls.Load())
	}
	cancel()
	<-done
}

func TestNew_RejectsBadOptions(t *testing.T) {
	t.Parallel()
	full := egress.Options{
		Resolver: &stubResolver{}, Applier: &stubApplier{}, Interval: time.Hour,
	}
	for _, mut := range []func(o egress.Options) egress.Options{
		func(o egress.Options) egress.Options { o.Resolver = nil; return o },
		func(o egress.Options) egress.Options { o.Applier = nil; return o },
		func(o egress.Options) egress.Options { o.Interval = 0; return o },
	} {
		if _, err := egress.New(mut(full)); err == nil {
			t.Error("expected error from missing option")
		}
	}
}
