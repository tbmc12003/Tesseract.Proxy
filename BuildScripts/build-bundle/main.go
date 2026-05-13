// Command build-bundle merges meta.yaml + brokers/*.yaml into a single
// bundle.yaml and (optionally) signs it with an Ed25519 detached
// signature (arch §13.2 / §13.4).
//
// The proxy's strict YAML loader (internal/profile.LoadAndVerify) is
// the authority on whether the output parses. A `make validate` step
// is encouraged in CI before publishing.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "build-bundle:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		metaPath      = flag.String("meta", "meta.yaml", "static bundle header")
		brokersDir    = flag.String("brokers", "brokers", "directory of broker YAMLs")
		outPath       = flag.String("out", "bundle.yaml", "output bundle path")
		sigPath       = flag.String("sig", "", "if set, also emit Ed25519 detached signature here")
		signerKeyPath = flag.String("signer-key", "", "Ed25519 PRIVATE key (PEM PKCS8). Required if -sig is set. For dev only — production uses AWS KMS sign.")
		bundleVersion = flag.String("bundle-version", "", "explicit bundle_version (default: date + 'dev')")
	)
	flag.Parse()

	meta, err := readYAMLMap(*metaPath)
	if err != nil {
		return fmt.Errorf("meta: %w", err)
	}
	brokers, err := loadBrokers(*brokersDir)
	if err != nil {
		return fmt.Errorf("brokers: %w", err)
	}

	if *bundleVersion == "" {
		*bundleVersion = time.Now().UTC().Format("2006-01-02") + "-dev"
	}
	meta["bundle_version"] = *bundleVersion
	meta["issued_at"] = time.Now().UTC().Format(time.RFC3339)
	meta["brokers"] = brokers

	rendered, err := yaml.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := os.WriteFile(*outPath, rendered, 0o640); err != nil {
		return fmt.Errorf("write %s: %w", *outPath, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d bytes, version %s)\n", *outPath, len(rendered), *bundleVersion)

	if *sigPath == "" {
		return nil
	}
	if *signerKeyPath == "" {
		return fmt.Errorf("-sig requires -signer-key")
	}
	priv, err := readEd25519Priv(*signerKeyPath)
	if err != nil {
		return fmt.Errorf("signer key: %w", err)
	}
	sig := ed25519.Sign(priv, rendered)
	if err := os.WriteFile(*sigPath, sig, 0o640); err != nil {
		return fmt.Errorf("write sig: %w", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d-byte Ed25519 signature)\n", *sigPath, len(sig))
	return nil
}

func readYAMLMap(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := yaml.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func loadBrokers(dir string) ([]any, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml") {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths) // deterministic order
	out := make([]any, 0, len(paths))
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var node map[string]any
		if err := yaml.Unmarshal(raw, &node); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		out = append(out, node)
	}
	return out, nil
}

func readEd25519Priv(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("expected PRIVATE KEY block, got %q", block.Type)
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := keyAny.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519 (got %T)", keyAny)
	}
	return priv, nil
}

// genTestKey is a debug helper invoked by `go run ./cmd/build-bundle -gen-test-key out.pem`.
// Not used in production. Production signing is AWS KMS Ed25519 (P0.4).
func init() {
	if len(os.Args) >= 3 && os.Args[1] == "-gen-test-key" {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(os.Args[2], pemBytes, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		// Also emit matching pubkey alongside, with .pub suffix.
		pubDER, _ := x509.MarshalPKIXPublicKey(priv.Public())
		pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
		_ = os.WriteFile(os.Args[2]+".pub", pubPEM, 0o644)
		fmt.Fprintf(os.Stderr, "wrote %s + %s.pub\n", os.Args[2], os.Args[2])
		os.Exit(0)
	}
}
