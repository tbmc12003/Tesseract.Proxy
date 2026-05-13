package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/equinomics/tesseract-proxy/internal/config"
)

const goldenYAML = `
listen:
  order_plane: "0.0.0.0:443"
  admin_plane: "127.0.0.1:8443"

mtls:
  server_cert: /etc/tesseract-proxy/certs/server.pem
  server_key:  /etc/tesseract-proxy/certs/server.key
  client_ca:   /etc/tesseract-proxy/certs/client-ca.pem
  allowed_order_serials: ["1001"]
  allowed_admin_serials: ["2001"]

profile_bundle:
  path:        /etc/tesseract-proxy/profiles/bundle.yaml
  sig_path:    /etc/tesseract-proxy/profiles/bundle.yaml.sig
  pubkey_path: /etc/tesseract-proxy/pubkey/equinomics-signing.pub
  refresh:
    enabled:  true
    url:      https://cfg.tesseract.in/bundles/latest.yaml
    interval: 6h

audit_log:
  path:         /var/log/tesseract-proxy/audit.log
  rotation_mb:  16
  retain_count: 14

log:
  level:  info
  format: json
`

func TestParse_Golden(t *testing.T) {
	t.Parallel()
	cfg, err := config.Parse(strings.NewReader(goldenYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if got, want := cfg.Listen.OrderPlane, "0.0.0.0:443"; got != want {
		t.Errorf("Listen.OrderPlane = %q, want %q", got, want)
	}
	if got, want := cfg.Listen.AdminPlane, "127.0.0.1:8443"; got != want {
		t.Errorf("Listen.AdminPlane = %q, want %q", got, want)
	}
	if got, want := cfg.ProfileBundle.Refresh.Interval.Std(), 6*time.Hour; got != want {
		t.Errorf("Refresh.Interval = %v, want %v", got, want)
	}
	if got, want := cfg.AuditLog.RotationMB, 16; got != want {
		t.Errorf("AuditLog.RotationMB = %d, want %d", got, want)
	}
}

func TestParse_AdminPlaneOptional(t *testing.T) {
	t.Parallel()
	y := strings.Replace(goldenYAML, `admin_plane: "127.0.0.1:8443"`, "", 1)
	cfg, err := config.Parse(strings.NewReader(y))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Listen.AdminPlane != "" {
		t.Errorf("AdminPlane = %q, want empty", cfg.Listen.AdminPlane)
	}
}

func TestParse_RefreshDisabledSkipsURLValidation(t *testing.T) {
	t.Parallel()
	y := strings.Replace(goldenYAML,
		`refresh:
    enabled:  true
    url:      https://cfg.tesseract.in/bundles/latest.yaml
    interval: 6h`,
		`refresh:
    enabled:  false`,
		1)
	if _, err := config.Parse(strings.NewReader(y)); err != nil {
		t.Fatalf("Parse: %v", err)
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "proxy.conf.yaml")
	if err := os.WriteFile(p, []byte(goldenYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(p); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	t.Parallel()
	_, err := config.Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil {
		t.Fatal("expected error opening nonexistent file")
	}
}

func TestParse_Rejects(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		yaml string
		want string // substring expected in error
	}{
		{
			name: "unknown top-level field",
			yaml: goldenYAML + "\nbogus_field: 1\n",
			want: "bogus_field",
		},
		{
			name: "unknown nested field",
			yaml: strings.Replace(goldenYAML,
				"rotation_mb:  16",
				"rotation_mb:  16\n  surprise:     true", 1),
			want: "surprise",
		},
		{
			name: "missing required mtls.server_cert",
			yaml: strings.Replace(goldenYAML,
				"server_cert: /etc/tesseract-proxy/certs/server.pem",
				`server_cert: ""`, 1),
			want: "mtls.server_cert",
		},
		{
			name: "invalid duration",
			yaml: strings.Replace(goldenYAML, "interval: 6h", "interval: twohours", 1),
			want: "invalid duration",
		},
		{
			name: "invalid host:port",
			yaml: strings.Replace(goldenYAML, `order_plane: "0.0.0.0:443"`, `order_plane: "no-port-here"`, 1),
			want: "listen.order_plane",
		},
		{
			name: "unknown log level",
			yaml: strings.Replace(goldenYAML, "level:  info", "level:  shouty", 1),
			want: "log.level",
		},
		{
			name: "unknown log format",
			yaml: strings.Replace(goldenYAML, "format: json", "format: xml", 1),
			want: "log.format",
		},
		{
			name: "refresh enabled without url",
			yaml: strings.Replace(goldenYAML,
				`refresh:
    enabled:  true
    url:      https://cfg.tesseract.in/bundles/latest.yaml
    interval: 6h`,
				`refresh:
    enabled:  true
    interval: 6h`, 1),
			want: "refresh.url",
		},
		{
			name: "refresh enabled with bad url",
			yaml: strings.Replace(goldenYAML,
				"https://cfg.tesseract.in/bundles/latest.yaml",
				"ftp://nope.invalid/", 1),
			want: "refresh.url",
		},
		{
			name: "refresh enabled with zero interval",
			yaml: strings.Replace(goldenYAML, "interval: 6h", "interval: 0s", 1),
			want: "refresh.interval",
		},
		{
			name: "audit_log.rotation_mb zero",
			yaml: strings.Replace(goldenYAML, "rotation_mb:  16", "rotation_mb:  0", 1),
			want: "audit_log.rotation_mb",
		},
		{
			name: "malformed yaml",
			yaml: "listen: [unbalanced",
			want: "parse yaml",
		},
		{
			name: "two yaml documents",
			yaml: goldenYAML + "\n---\nlisten: {}\n",
			want: "additional document",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := config.Parse(strings.NewReader(tc.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestListenChanged(t *testing.T) {
	t.Parallel()
	a, err := config.Parse(strings.NewReader(goldenYAML))
	if err != nil {
		t.Fatal(err)
	}
	b, err := config.Parse(strings.NewReader(goldenYAML))
	if err != nil {
		t.Fatal(err)
	}
	if a.ListenChanged(b) {
		t.Errorf("identical configs reported as changed")
	}
	b.Listen.OrderPlane = "0.0.0.0:8443"
	if !a.ListenChanged(b) {
		t.Errorf("differing OrderPlane not detected")
	}
}
