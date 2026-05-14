package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// proxyClient holds an mTLS-authenticated HTTP client + base URL for the
// proxy's /admin/* endpoints. Built lazily so admin-ui can start even
// when the operator hasn't wired the certs yet (R7.x endpoints surface
// 424 in that case via deployConfig.mtlsMissing).
type proxyClient struct {
	cfg     *deployConfig
	baseURL string
	hc      *http.Client
}

// newProxyClient validates inputs, builds a TLS config, and returns a
// ready-to-use *http.Client. Returns an error if any required path is
// missing/unreadable or the cert/CA fail to parse.
func newProxyClient(cfg *deployConfig) (*proxyClient, error) {
	if missing := cfg.mtlsMissing(); len(missing) > 0 {
		return nil, fmt.Errorf("mTLS not configured: %s", strings.Join(missing, ", "))
	}

	pair, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("load client cert/key: %w", err)
	}

	caBytes, err := os.ReadFile(cfg.ClientCA)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, errors.New("CA bundle: no PEM certificates parsed")
	}

	// The server cert's SAN is the Lightsail IP (gen-mtls.sh --lightsail-ip).
	// Go's TLS client uses the URL host for SAN matching, so leaving
	// ServerName empty works — IP SAN matching kicks in.
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{pair},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}

	transport := &http.Transport{
		TLSClientConfig:       tlsCfg,
		MaxIdleConns:          4,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 0, // SSE: no header timeout once stream is open
		ExpectContinueTimeout: 1 * time.Second,
	}

	port := cfg.ProxyPort
	if port == 0 {
		port = 443
	}
	base := (&url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(cfg.LightsailIP, strconv.Itoa(port)),
	}).String()

	return &proxyClient{
		cfg:     cfg,
		baseURL: base,
		hc: &http.Client{
			Transport: transport,
			// No top-level timeout — R7.1 SSE streams indefinitely.
			// Per-request timeouts come from ctx in callers.
		},
	}, nil
}

// url joins a path onto the proxy base URL. Path must start with '/'.
func (p *proxyClient) url(path string) string {
	return p.baseURL + path
}

// certInfo returns a short description of the loaded client cert.
// Used by /api/proxy/check; safe to expose over loopback.
type certInfo struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	NotAfter   time.Time `json:"not_after"`
	SerialHex  string    `json:"serial_hex"`
	BaseURL    string    `json:"base_url"`
	CAFile     string    `json:"ca_file"`
	CertFile   string    `json:"cert_file"`
}

func (p *proxyClient) certInfo() (*certInfo, error) {
	if len(p.hc.Transport.(*http.Transport).TLSClientConfig.Certificates) == 0 {
		return nil, errors.New("no client cert loaded")
	}
	tlsCert := p.hc.Transport.(*http.Transport).TLSClientConfig.Certificates[0]
	if len(tlsCert.Certificate) == 0 {
		return nil, errors.New("client cert has no leaf")
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf: %w", err)
	}
	return &certInfo{
		Subject:   leaf.Subject.String(),
		Issuer:    leaf.Issuer.String(),
		NotAfter:  leaf.NotAfter,
		SerialHex: fmt.Sprintf("%x", leaf.SerialNumber),
		BaseURL:   p.baseURL,
		CAFile:    p.cfg.ClientCA,
		CertFile:  p.cfg.ClientCert,
	}, nil
}

