// Package egress generates the outbound-allowlist nftables ruleset from
// the live broker bundle and applies it (arch §7.6, §13.3).
//
// The proxy is allowed to dial *only* the broker hosts named in the
// bundle. nftables enforces this at the kernel level so a compromised
// binary cannot exfiltrate to an arbitrary destination.
//
// This package owns three things:
//
//  1. Resolution: turn the bundle's host list into a concrete IP set
//     (DNS, IPv4 + IPv6).
//  2. Rendering: emit an nft ruleset string allowing outbound TCP/443 to
//     exactly that IP set, plus established/related and loopback.
//  3. Orchestration: refresh on a 5-minute timer and on every bundle
//     swap; apply via an injected Applier so the actual `nft -f -`
//     subprocess (or the tesseract-proxy-egress companion binary) is
//     decoupled from the orchestration logic and testable.
//
// On a partial resolution failure (one host doesn't resolve) the apply is
// **not** attempted — leaving the previous rules in place is safer than
// publishing a ruleset that silently omits a host the bundle considers
// allowed.
package egress

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Resolver is the DNS lookup layer. Production uses net.DefaultResolver;
// tests inject a stub returning fixed IPs.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]net.IP, error)
}

// Applier publishes a rendered ruleset. Production wraps `nft -f -` (or
// invokes the tesseract-proxy-egress companion binary); tests record
// what was asked.
type Applier interface {
	Apply(ctx context.Context, ruleset string) error
}

// Options configures a Generator. All fields except Logger are required.
type Options struct {
	Resolver Resolver
	Applier  Applier
	// Interval is the DNS-refresh cadence. Arch §6.3 calls for 5 min.
	Interval time.Duration
	Logger   *slog.Logger
}

// Generator orchestrates resolve + render + apply. Call UpdateHosts on
// every bundle swap; call Run in a goroutine to drive periodic refresh.
type Generator struct {
	opts Options

	mu    sync.Mutex
	hosts []string

	poke chan struct{}
}

// New constructs a Generator.
func New(opts Options) (*Generator, error) {
	if opts.Resolver == nil {
		return nil, errors.New("egress: Resolver is required")
	}
	if opts.Applier == nil {
		return nil, errors.New("egress: Applier is required")
	}
	if opts.Interval <= 0 {
		return nil, errors.New("egress: Interval must be > 0")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Generator{opts: opts, poke: make(chan struct{}, 1)}, nil
}

// UpdateHosts replaces the host set and schedules an immediate Tick. Call
// this on every bundle swap from the OnSwap hook of bundleupd.Updater.
func (g *Generator) UpdateHosts(hosts []string) {
	deduped := dedupSorted(hosts)
	g.mu.Lock()
	g.hosts = deduped
	g.mu.Unlock()
	select {
	case g.poke <- struct{}{}:
	default:
	}
}

// Run drives periodic refresh + on-poke updates until ctx is cancelled.
func (g *Generator) Run(ctx context.Context) error {
	ticker := time.NewTicker(g.opts.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		case <-g.poke:
		}
		if err := g.Tick(ctx); err != nil {
			g.opts.Logger.Warn("egress refresh failed; keeping current ruleset",
				"err", err.Error())
		}
	}
}

// Tick performs one resolve + render + apply pass.
func (g *Generator) Tick(ctx context.Context) error {
	g.mu.Lock()
	hosts := append([]string(nil), g.hosts...)
	g.mu.Unlock()

	if len(hosts) == 0 {
		// No hosts → nothing to apply. We don't push an "allow nothing"
		// ruleset because that would brick the box if called before the
		// first bundle has been loaded.
		return nil
	}

	ips, err := ResolveAll(ctx, g.opts.Resolver, hosts)
	if err != nil {
		return fmt.Errorf("resolve: %w", err)
	}
	ruleset := Render(hosts, ips)
	if err := g.opts.Applier.Apply(ctx, ruleset); err != nil {
		return fmt.Errorf("apply: %w", err)
	}
	return nil
}

// ResolveAll resolves every host and returns the deduplicated IP set. A
// resolution failure on any host returns an error rather than silently
// omitting that host's IPs from the allowlist.
func ResolveAll(ctx context.Context, r Resolver, hosts []string) ([]net.IP, error) {
	seen := map[string]net.IP{}
	for _, h := range hosts {
		ips, err := r.LookupHost(ctx, h)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", h, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("resolve %s: no addresses", h)
		}
		for _, ip := range ips {
			seen[ip.String()] = ip
		}
	}
	out := make([]net.IP, 0, len(seen))
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, seen[k])
	}
	return out, nil
}

// Render produces the nft ruleset text. The output is deterministic
// (sorted IPs) so a no-change refresh produces byte-identical input to
// `nft -f -` — handy for change detection at the Applier level.
func Render(hosts []string, ips []net.IP) string {
	v4, v6 := splitFamilies(ips)

	var sb strings.Builder
	sb.WriteString("# Tesseract proxy egress ruleset — generated, do not edit.\n")
	sb.WriteString("# Allowed broker hosts:\n")
	for _, h := range hosts {
		fmt.Fprintf(&sb, "#   %s\n", h)
	}
	sb.WriteString("table inet tesseract_egress {\n")
	sb.WriteString("\tchain output {\n")
	sb.WriteString("\t\ttype filter hook output priority 0; policy drop;\n")
	sb.WriteString("\t\tct state established,related accept\n")
	sb.WriteString("\t\toif lo accept\n")
	if len(v4) > 0 {
		sb.WriteString("\t\ttcp dport 443 ip daddr { ")
		sb.WriteString(strings.Join(v4, ", "))
		sb.WriteString(" } accept\n")
	}
	if len(v6) > 0 {
		sb.WriteString("\t\ttcp dport 443 ip6 daddr { ")
		sb.WriteString(strings.Join(v6, ", "))
		sb.WriteString(" } accept\n")
	}
	sb.WriteString("\t}\n")
	sb.WriteString("}\n")
	return sb.String()
}

func splitFamilies(ips []net.IP) (v4, v6 []string) {
	for _, ip := range ips {
		if four := ip.To4(); four != nil {
			v4 = append(v4, four.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}
	return v4, v6
}

func dedupSorted(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
