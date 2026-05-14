// admin-ui is a loopback-only desktop tool for editing Tesseract broker
// profiles. It binds 127.0.0.1 only — there is no auth, because there is
// no remote reach. See README.md.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

const defaultPort = 47821

func main() {
	port := flag.Int("port", defaultPort, "loopback port to bind")
	configDir := flag.String("config-dir", "", "path to tesseract-proxy-config (auto-detected if empty)")
	noBrowser := flag.Bool("no-browser", false, "do not launch the default browser")
	flag.Parse()

	resolvedCfg, err := resolveConfigDir(*configDir)
	if err != nil {
		log.Fatalf("config-dir: %v", err)
	}
	log.Printf("config-dir: %s", resolvedCfg)

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("loopback bind failed (%s): %v\nadmin-ui refuses to bind any other interface.", addr, err)
	}
	if !isLoopback(ln.Addr()) {
		_ = ln.Close()
		log.Fatalf("listener resolved to non-loopback address %s — refusing to start", ln.Addr())
	}

	dep, err := loadDeployConfig(resolvedCfg)
	if err != nil {
		log.Fatalf("deploy config: %v", err)
	}
	if missing := dep.missing(); len(missing) > 0 {
		log.Printf("deploy.local.yaml missing %v — Publish will return 424 until set", missing)
	}
	if missing := dep.mtlsMissing(); len(missing) > 0 {
		log.Printf("mTLS to proxy not configured: %v — audit/health endpoints will return 424 until set", missing)
	} else {
		log.Printf("mTLS to proxy: %s (cert=%s, ca=%s)", dep.LightsailIP, dep.ClientCert, dep.ClientCA)
	}

	srv := newServer(resolvedCfg, dep)
	url := fmt.Sprintf("http://%s/", addr)
	log.Printf("admin-ui listening on %s", url)

	if !*noBrowser {
		go func() {
			time.Sleep(300 * time.Millisecond)
			if err := openBrowser(url); err != nil {
				log.Printf("browser launch failed: %v (open %s manually)", err, url)
			}
		}()
	}

	httpSrv := &http.Server{
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func isLoopback(a net.Addr) bool {
	tcp, ok := a.(*net.TCPAddr)
	if !ok {
		return false
	}
	return tcp.IP.IsLoopback()
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}

// resolveConfigDir returns the explicit flag value if set, otherwise walks
// upward from the current working directory looking for
// `tesseract-proxy-config/brokers`.
func resolveConfigDir(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(filepath.Join(explicit, "brokers")); err != nil {
			return "", fmt.Errorf("brokers/ not found under %s: %w", explicit, err)
		}
		return explicit, nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		candidate := filepath.Join(dir, "tesseract-proxy-config")
		if st, err := os.Stat(filepath.Join(candidate, "brokers")); err == nil && st.IsDir() {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not auto-detect tesseract-proxy-config from %s; pass --config-dir", wd)
		}
		dir = parent
	}
}
