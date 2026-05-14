package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// confirmPhrase is the literal string the client must echo to publish.
// Server-side check; the frontend modal enforces the same on the way in.
const confirmPhrase = "DEPLOY"

type publishHandler struct {
	cfgDir string
	cfg    *deployConfig

	// Single-flight: one publish at a time. Prevents racing reload-bundle
	// invocations clobbering each other's bundle.yaml on disk.
	mu sync.Mutex
}

type publishReq struct {
	Confirm string `json:"confirm"`
}

func (h *publishHandler) handle(w http.ResponseWriter, r *http.Request) {
	var req publishReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Confirm != confirmPhrase {
		writeErr(w, http.StatusPreconditionFailed,
			fmt.Sprintf("confirm phrase must be exactly %q", confirmPhrase))
		return
	}
	if missing := h.cfg.missing(); len(missing) > 0 {
		writeErr(w, http.StatusFailedDependency,
			"deploy.local.yaml is missing required fields: "+strings.Join(missing, ", "))
		return
	}
	if !h.mu.TryLock() {
		writeErr(w, http.StatusConflict, "another publish is already in progress")
		return
	}
	defer h.mu.Unlock()

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming not supported")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	emit := func(format string, args ...any) {
		fmt.Fprintf(w, format, args...)
		flusher.Flush()
	}

	emit("==> publish started %s\n", time.Now().Format(time.RFC3339))
	emit("    bundle out: %s\n", h.cfg.BundleOut)
	emit("    sig out:    %s\n", h.cfg.SigOut)
	emit("    target:     ec2-user@%s\n\n", h.cfg.LightsailIP)

	if err := os.MkdirAll(filepath.Dir(h.cfg.BundleOut), 0o755); err != nil {
		emit("FAILED: mkdir bundle dir: %v\n", err)
		return
	}

	// Step 1: build bundle.
	emit("==> step 1/2: build-bundle\n")
	buildCmd := exec.CommandContext(r.Context(), "go", "run", "./cmd/build-bundle",
		"-meta", filepath.Join(h.cfgDir, "meta.yaml"),
		"-brokers", filepath.Join(h.cfgDir, "brokers"),
		"-out", h.cfg.BundleOut,
		"-sig", h.cfg.SigOut,
		"-signer-key", h.cfg.SignerKey,
	)
	buildCmd.Dir = h.cfg.ProxyRepo
	if err := streamCmd(r.Context(), buildCmd, w, flusher); err != nil {
		emit("\nFAILED at build-bundle: %v\n", err)
		return
	}

	// Step 2: reload bundle on Lightsail.
	emit("\n==> step 2/2: reload-bundle.sh\n")
	reloadCmd := exec.CommandContext(r.Context(), "bash", h.cfg.ReloadScript,
		"--bundle", h.cfg.BundleOut,
		"--sig", h.cfg.SigOut,
		"--lightsail-ip", h.cfg.LightsailIP,
		"--pubkey", h.cfg.PubKey,
		"--ssh-key", h.cfg.SSHKey,
	)
	if err := streamCmd(r.Context(), reloadCmd, w, flusher); err != nil {
		emit("\nFAILED at reload-bundle: %v\n", err)
		return
	}

	if err := writeSnapshot(h.cfg); err != nil {
		emit("\n[warn] failed to snapshot bundle for future diffs: %v\n", err)
	} else {
		emit("\n==> snapshot saved to %s\n", snapshotPath(h.cfg))
	}

	emit("\n==> publish complete %s\n", time.Now().Format(time.RFC3339))
}

// streamCmd runs cmd, copying stdout+stderr line-buffered to w with a
// flush after each line so the browser sees progress in real time.
func streamCmd(ctx context.Context, cmd *exec.Cmd, w io.Writer, flusher http.Flusher) error {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	var wg sync.WaitGroup
	pump := func(prefix string, r io.Reader) {
		defer wg.Done()
		s := bufio.NewScanner(r)
		s.Buffer(make([]byte, 64*1024), 1<<20)
		for s.Scan() {
			fmt.Fprintf(w, "%s%s\n", prefix, s.Text())
			flusher.Flush()
		}
	}
	wg.Add(2)
	go pump("", stdout)
	go pump("[stderr] ", stderr)
	wg.Wait()
	return cmd.Wait()
}
