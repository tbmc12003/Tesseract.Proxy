package egress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
)

// NftApplier shells out to `nft -f -` with the rendered ruleset on stdin.
// Use NewNftApplier on production hosts; tests inject a stub Applier.
type NftApplier struct {
	// Path overrides the binary path. Default: "nft" (resolved via PATH).
	Path string
}

// Apply runs `nft -f -` with ruleset on stdin. The combined stdout/stderr
// is surfaced in the error on non-zero exit so the operator sees the nft
// parser's diagnostics.
func (a *NftApplier) Apply(ctx context.Context, ruleset string) error {
	bin := a.Path
	if bin == "" {
		bin = "nft"
	}
	cmd := exec.CommandContext(ctx, bin, "-f", "-")
	cmd.Stdin = bytes.NewReader([]byte(ruleset))
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft apply: %w (output: %s)", err, combined.String())
	}
	return nil
}

// HelperApplier invokes the standalone tesseract-proxy-egress companion
// binary, passing the ruleset on stdin. This is the production path
// when running under systemd with privsep: the proxy itself has no
// CAP_NET_ADMIN; only the helper does.
type HelperApplier struct {
	// Path is the companion binary, e.g. /usr/local/bin/tesseract-proxy-egress.
	Path string
}

// Apply runs the helper with stdin = ruleset.
func (a *HelperApplier) Apply(ctx context.Context, ruleset string) error {
	if a.Path == "" {
		return errors.New("egress: HelperApplier.Path is required")
	}
	cmd := exec.CommandContext(ctx, a.Path)
	cmd.Stdin = bytes.NewReader([]byte(ruleset))
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("egress helper: %w (output: %s)", err, combined.String())
	}
	return nil
}
