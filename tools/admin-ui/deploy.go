package main

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// deployConfig holds everything the publish flow needs. Loaded from
// deploy.local.yaml inside the tesseract-proxy-config directory; flags
// on admin-ui can override individual fields.
type deployConfig struct {
	LightsailIP  string `yaml:"lightsail_ip"`
	SSHKey       string `yaml:"ssh_key"`
	SignerKey    string `yaml:"signer_key"`
	PubKey       string `yaml:"pubkey"`
	BundleOut    string `yaml:"bundle_out"`
	SigOut       string `yaml:"sig_out"`
	ProxyRepo    string `yaml:"proxy_repo"`
	ReloadScript string `yaml:"reload_script"`

	// mTLS material used by the admin-ui to talk to the proxy's
	// /admin/* endpoints over the existing ECDSA trust chain (R7.x).
	// PEM-only; gen-mtls.sh emits both PEM and P12, admin-ui takes PEM.
	ClientCert string `yaml:"client_cert"`
	ClientKey  string `yaml:"client_key"`
	ClientCA   string `yaml:"client_ca"`
	// ProxyPort defaults to 443 if unset.
	ProxyPort int `yaml:"proxy_port"`
}

// loadDeployConfig reads <cfgDir>/deploy.local.yaml if present and fills
// in defaults derived from cfgDir for any fields the file omits.
//
// Required-but-unset fields (lightsail_ip, ssh_key, signer_key) are NOT
// validated here — the publish handler reports them as a 412 at request
// time so the binary can still start without a deploy config.
func loadDeployConfig(cfgDir string) (*deployConfig, error) {
	cfg := &deployConfig{}
	path := filepath.Join(cfgDir, "deploy.local.yaml")
	if raw, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(raw, cfg); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	// Workspace = parent of cfgDir; src = cfgDir/.. typically.
	src := filepath.Dir(cfgDir)
	workspace := filepath.Dir(src)

	def := func(target *string, val string) {
		if *target == "" {
			*target = val
		}
	}
	def(&cfg.ProxyRepo, filepath.Join(src, "tesseract-proxy"))
	def(&cfg.ReloadScript, filepath.Join(src, "release", "scripts", "reload-bundle.sh"))
	def(&cfg.PubKey, filepath.Join(workspace, "releases", "keys", "signing.pub"))
	def(&cfg.BundleOut, filepath.Join(workspace, "releases", "staging", "bundle.yaml"))
	def(&cfg.SigOut, filepath.Join(workspace, "releases", "staging", "bundle.yaml.sig"))
	def(&cfg.ClientCert, filepath.Join(workspace, "releases", "mtls", "client.pem"))
	def(&cfg.ClientKey, filepath.Join(workspace, "releases", "mtls", "client.key"))
	def(&cfg.ClientCA, filepath.Join(workspace, "releases", "mtls", "ca.pem"))
	if cfg.ProxyPort == 0 {
		cfg.ProxyPort = 443
	}
	return cfg, nil
}

// missing reports required-but-unset publish fields. Returned 412 by
// /api/publish to keep that flow honest.
func (c *deployConfig) missing() []string {
	var m []string
	if c.LightsailIP == "" {
		m = append(m, "lightsail_ip")
	}
	if c.SSHKey == "" {
		m = append(m, "ssh_key")
	}
	if c.SignerKey == "" {
		m = append(m, "signer_key")
	}
	return m
}

// mtlsMissing reports required-but-unset / unreadable fields for the
// proxy mTLS client. Returned 424 by R7.x endpoints when the operator
// has not yet wired admin-ui's client cert.
func (c *deployConfig) mtlsMissing() []string {
	var m []string
	if c.LightsailIP == "" {
		m = append(m, "lightsail_ip")
	}
	for _, f := range []struct {
		name string
		path string
	}{
		{"client_cert", c.ClientCert},
		{"client_key", c.ClientKey},
		{"client_ca", c.ClientCA},
	} {
		if f.path == "" {
			m = append(m, f.name)
			continue
		}
		if _, err := os.Stat(f.path); err != nil {
			m = append(m, f.name+" (unreadable: "+f.path+")")
		}
	}
	return m
}
