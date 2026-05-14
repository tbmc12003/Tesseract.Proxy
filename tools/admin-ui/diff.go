package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// diffHandler returns the unified diff between the bundle that would be
// produced by the current working tree (broker YAMLs in cfgDir) and the
// last successfully-published bundle snapshot.
//
// The snapshot is written next to BundleOut as `last-published.bundle.yaml`
// at the end of a successful POST /api/publish.
type diffHandler struct {
	cfgDir string
	cfg    *deployConfig
}

type diffResp struct {
	Current      string `json:"current"`
	Previous     string `json:"previous"`
	Unified      string `json:"unified"`
	PreviousPath string `json:"previous_path"`
	NoPrevious   bool   `json:"no_previous"`
}

func (h *diffHandler) handle(w http.ResponseWriter, r *http.Request) {
	// Build the would-be bundle into a temp file so we don't disturb
	// BundleOut (which is the last *built* bundle, not the last published).
	tmpDir, err := os.MkdirTemp("", "admin-ui-diff-")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "mkdtemp: "+err.Error())
		return
	}
	defer os.RemoveAll(tmpDir)

	tmpBundle := filepath.Join(tmpDir, "bundle.yaml")
	tmpSig := filepath.Join(tmpDir, "bundle.yaml.sig")

	// build-bundle requires a signer key. If the user hasn't configured one
	// yet we still want to show a diff, so fall back to a throwaway key.
	signer := h.cfg.SignerKey
	if signer == "" || !fileExists(signer) {
		k, err := writeThrowawaySigner(tmpDir)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "signer fallback: "+err.Error())
			return
		}
		signer = k
	}

	var stderr bytes.Buffer
	cmd := exec.CommandContext(r.Context(), "go", "run", "./cmd/build-bundle",
		"-meta", filepath.Join(h.cfgDir, "meta.yaml"),
		"-brokers", filepath.Join(h.cfgDir, "brokers"),
		"-out", tmpBundle,
		"-sig", tmpSig,
		"-signer-key", signer,
	)
	cmd.Dir = h.cfg.ProxyRepo
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		writeErr(w, http.StatusInternalServerError,
			fmt.Sprintf("build-bundle failed: %v\n%s", err, stderr.String()))
		return
	}

	currentBytes, err := os.ReadFile(tmpBundle)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "read current bundle: "+err.Error())
		return
	}
	current := string(currentBytes)

	prevPath := snapshotPath(h.cfg)
	resp := diffResp{Current: current, PreviousPath: prevPath}

	prevBytes, err := os.ReadFile(prevPath)
	if err != nil {
		if os.IsNotExist(err) {
			resp.NoPrevious = true
			resp.Unified = unifiedDiff("(no previous)", "current bundle", "", current)
			writeJSON(w, http.StatusOK, resp)
			return
		}
		writeErr(w, http.StatusInternalServerError, "read previous bundle: "+err.Error())
		return
	}
	resp.Previous = string(prevBytes)
	resp.Unified = unifiedDiff("last-published bundle.yaml", "current bundle.yaml",
		resp.Previous, resp.Current)
	writeJSON(w, http.StatusOK, resp)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// writeThrowawaySigner mints an ECDSA P-256 key purely so build-bundle can
// produce a signature; the signature is discarded — we only care about the
// bundle YAML content for the diff.
func writeThrowawaySigner(dir string) (string, error) {
	path := filepath.Join(dir, "throwaway.key")
	cmd := exec.Command("openssl", "genpkey",
		"-algorithm", "EC",
		"-pkeyopt", "ec_paramgen_curve:P-256",
		"-out", path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, stderr.String())
	}
	return path, nil
}

// snapshotPath returns where we cache the last-published bundle.
func snapshotPath(cfg *deployConfig) string {
	return filepath.Join(filepath.Dir(cfg.BundleOut), "last-published.bundle.yaml")
}

// writeSnapshot is called by the publish handler on success.
func writeSnapshot(cfg *deployConfig) error {
	src, err := os.ReadFile(cfg.BundleOut)
	if err != nil {
		return err
	}
	dst := snapshotPath(cfg)
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, src, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// --- unified line diff (LCS-based) -----------------------------------------

// unifiedDiff returns a GNU-unified-diff-style string with @@ hunks and
// +/-/' ' line prefixes. Context = 3 lines. Implementation is straight
// LCS DP — fine for files of a few hundred lines.
func unifiedDiff(aName, bName, a, b string) string {
	aLines := splitKeepEOL(a)
	bLines := splitKeepEOL(b)
	ops := lcsDiff(aLines, bLines)

	var sb strings.Builder
	fmt.Fprintf(&sb, "--- %s\n+++ %s\n", aName, bName)

	const ctx = 3
	// Mark each op as "interesting" if it's within ctx of a change.
	n := len(ops)
	keep := make([]bool, n)
	for i, o := range ops {
		if o.op == '=' {
			continue
		}
		lo := i - ctx
		if lo < 0 {
			lo = 0
		}
		hi := i + ctx + 1
		if hi > n {
			hi = n
		}
		for k := lo; k < hi; k++ {
			keep[k] = true
		}
	}

	// Emit consecutive runs of `keep==true` as one hunk each.
	i := 0
	for i < n {
		if !keep[i] {
			i++
			continue
		}
		j := i
		for j < n && keep[j] {
			j++
		}
		writeHunk(&sb, ops, i, j)
		i = j
	}
	return sb.String()
}

type diffOp struct {
	op   byte // '=', '+', '-'
	line string
}

func splitKeepEOL(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i+1])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func lcsDiff(a, b []string) []diffOp {
	n, m := len(a), len(b)
	// DP table of LCS lengths.
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}
	var ops []diffOp
	i, j := 0, 0
	for i < n && j < m {
		if a[i] == b[j] {
			ops = append(ops, diffOp{'=', a[i]})
			i++
			j++
		} else if dp[i+1][j] >= dp[i][j+1] {
			ops = append(ops, diffOp{'-', a[i]})
			i++
		} else {
			ops = append(ops, diffOp{'+', b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, diffOp{'-', a[i]})
	}
	for ; j < m; j++ {
		ops = append(ops, diffOp{'+', b[j]})
	}
	return ops
}

func writeHunk(sb *strings.Builder, ops []diffOp, lo, hi int) {
	// Compute starting line numbers in a and b.
	aStart, bStart := 1, 1
	for k := 0; k < lo; k++ {
		switch ops[k].op {
		case '=':
			aStart++
			bStart++
		case '-':
			aStart++
		case '+':
			bStart++
		}
	}
	var aLen, bLen int
	for k := lo; k < hi; k++ {
		switch ops[k].op {
		case '=':
			aLen++
			bLen++
		case '-':
			aLen++
		case '+':
			bLen++
		}
	}
	fmt.Fprintf(sb, "@@ -%d,%d +%d,%d @@\n", aStart, aLen, bStart, bLen)
	for k := lo; k < hi; k++ {
		line := ops[k].line
		trailing := ""
		if !strings.HasSuffix(line, "\n") {
			trailing = "\n\\ No newline at end of file\n"
		}
		prefix := byte(' ')
		switch ops[k].op {
		case '-':
			prefix = '-'
		case '+':
			prefix = '+'
		}
		sb.WriteByte(prefix)
		sb.WriteString(line)
		sb.WriteString(trailing)
	}
}
