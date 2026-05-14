// Command admin-curl is a minimal mTLS HTTP client for hitting the
// proxy's /admin/* endpoints from any machine that has Go installed.
//
// Why this exists: a tiny algorithm-agnostic Go client for the admin
// surface that any operator with Go installed can use, regardless of OS
// or curl flavour. (Historical note: this tool was originally written
// when client certs were Ed25519 and Schannel could not load them. The
// mTLS chain is now ECDSA P-256 end-to-end and Schannel-compatible, but
// this tool is still handy for scripted admin calls.)
//
// Usage:
//
//	go run ./cmd/admin-curl \
//	    -ip 13.207.35.97 \
//	    -ca   ../../../releases/mtls/root-ca/ca.pem \
//	    -cert ../../../releases/mtls/tesseract/client.pem \
//	    -key  ../../../releases/mtls/tesseract/client.key \
//	    -path /admin/healthz
//
// With a host alias (using the cert's SAN matching the IP via TLS
// ServerName = "tesseract-proxy"):
//
//	go run ./cmd/admin-curl -ip 13.207.35.97 -ca … -cert … -key … \
//	    -path /admin/status
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	var (
		ip   = flag.String("ip", "", "Lightsail public IP (required)")
		port = flag.Int("port", 443, "destination port")
		ca   = flag.String("ca", "", "path to CA cert PEM (required)")
		cert = flag.String("cert", "", "path to client cert PEM (required)")
		key  = flag.String("key", "", "path to client key PEM (required)")
		path = flag.String("path", "/admin/healthz", "request path")
		verb = flag.String("method", "GET", "HTTP method")
	)
	flag.Parse()

	if *ip == "" || *ca == "" || *cert == "" || *key == "" {
		fmt.Fprintln(os.Stderr, "missing required flag; see -h")
		os.Exit(2)
	}

	caPEM, err := os.ReadFile(*ca)
	if err != nil {
		fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		fatal(fmt.Errorf("no PEM blocks parsed from %s", *ca))
	}
	clientCert, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		fatal(err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      pool,
			Certificates: []tls.Certificate{clientCert},
			// The proxy's server cert has IP SAN = <ip>. Setting
			// ServerName to the IP matches that SAN at verify time.
			ServerName: *ip,
		},
	}
	client := &http.Client{Transport: tr}

	url := fmt.Sprintf("https://%s:%d%s", *ip, *port, *path)
	req, err := http.NewRequest(*verb, url, nil)
	if err != nil {
		fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		fatal(err)
	}
	defer resp.Body.Close()

	fmt.Fprintf(os.Stderr, "HTTP %d\n", resp.StatusCode)
	for k, vv := range resp.Header {
		for _, v := range vv {
			fmt.Fprintf(os.Stderr, "%s: %s\n", k, v)
		}
	}
	fmt.Fprintln(os.Stderr)
	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		fatal(err)
	}
	fmt.Fprintln(os.Stdout)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "fatal:", err)
	os.Exit(1)
}
