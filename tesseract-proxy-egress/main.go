// Command tesseract-proxy-egress reads the active broker bundle,
// resolves each broker host, and applies an nftables ruleset allowing
// outbound TCP/443 only to those IPs (arch §7.6, P1.3).
//
// Production deployment: this binary runs as a separate systemd unit
// with CAP_NET_ADMIN; the proxy itself runs with no capabilities. The
// proxy emits a `SIGUSR1` (or invokes this binary directly via its
// admin hook) on every bundle swap to refresh the ruleset.
//
// The rendering logic is a deliberate copy of internal/egress.Render in
// the proxy repo. The two are different trust boundaries and don't
// share code — drift is detected by a comparison test in CI rather than
// by import.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "tesseract-proxy-egress:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		bundlePath = flag.String("bundle", "", "path to active bundle.yaml (required)")
		apply      = flag.Bool("apply", false, "if set, pipe the ruleset to `nft -f -`; else print to stdout")
		nftPath    = flag.String("nft", "nft", "path to the nft binary")
		timeout    = flag.Duration("timeout", 30*time.Second, "deadline for resolve+apply")
	)
	flag.Parse()
	if *bundlePath == "" {
		return fmt.Errorf("--bundle is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	hosts, err := readBundleHosts(*bundlePath)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}
	if len(hosts) == 0 {
		return fmt.Errorf("bundle has no enabled brokers — refusing to apply a deny-all ruleset")
	}

	ips, err := resolveAll(ctx, net.DefaultResolver, hosts)
	if err != nil {
		return fmt.Errorf("resolve: %w", err)
	}
	ruleset := render(hosts, ips)
	if !*apply {
		fmt.Print(ruleset)
		return nil
	}
	return applyNft(ctx, *nftPath, ruleset)
}

// readBundleHosts pulls the host list from a bundle YAML. Only enabled
// brokers are included — disabled ones must not appear in the egress
// allowlist.
func readBundleHosts(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Brokers []struct {
			ID      string `yaml:"id"`
			Host    string `yaml:"host"`
			Enabled bool   `yaml:"enabled"`
		} `yaml:"brokers"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var hosts []string
	for _, b := range doc.Brokers {
		if !b.Enabled {
			continue
		}
		hosts = append(hosts, b.Host)
	}
	sort.Strings(hosts)
	return hosts, nil
}

func resolveAll(ctx context.Context, r *net.Resolver, hosts []string) ([]net.IP, error) {
	seen := map[string]net.IP{}
	for _, h := range hosts {
		addrs, err := r.LookupHost(ctx, h)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", h, err)
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("resolve %s: no addresses", h)
		}
		for _, a := range addrs {
			ip := net.ParseIP(a)
			if ip == nil {
				continue
			}
			seen[ip.String()] = ip
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]net.IP, 0, len(keys))
	for _, k := range keys {
		out = append(out, seen[k])
	}
	return out, nil
}

// render produces the nft ruleset. Kept byte-identical in shape to the
// proxy's internal/egress.Render output so the comparison test passes.
func render(hosts []string, ips []net.IP) string {
	var v4, v6 []string
	for _, ip := range ips {
		if four := ip.To4(); four != nil {
			v4 = append(v4, four.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}
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

func applyNft(ctx context.Context, nft, ruleset string) error {
	cmd := exec.CommandContext(ctx, nft, "-f", "-")
	cmd.Stdin = bytes.NewReader([]byte(ruleset))
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft: %w (output: %s)", err, combined.String())
	}
	return nil
}
