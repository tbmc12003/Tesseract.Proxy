// Command build-bundle merges meta.yaml + brokers/*.yaml into a single
// bundle.yaml and (optionally) signs it with an ECDSA P-256 detached
// signature (ASN.1 DER over SHA-256(bundle)).
//
// The proxy's strict YAML loader (internal/profile.LoadAndVerify) is the
// authority on whether the output parses.
//
// Signature scheme:
//
//   sig = ecdsa.SignASN1(rand, priv, SHA256(bundle))
//
// matches `openssl dgst -sha256 -sign key.pem -out sig.bin bundle.yaml`
// and is verified by `openssl dgst -sha256 -verify pub.pem -signature sig.bin`.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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
		sigPath       = flag.String("sig", "", "if set, also emit ECDSA P-256 detached signature here (ASN.1 DER)")
		signerKeyPath = flag.String("signer-key", "", "ECDSA P-256 PRIVATE key (PEM PKCS8). Required if -sig is set.")
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
	priv, err := readECDSAPriv(*signerKeyPath)
	if err != nil {
		return fmt.Errorf("signer key: %w", err)
	}
	h := sha256.Sum256(rendered)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	if err := os.WriteFile(*sigPath, sig, 0o640); err != nil {
		return fmt.Errorf("write sig: %w", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d-byte ECDSA P-256 DER signature)\n", *sigPath, len(sig))
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

func readECDSAPriv(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	var keyAny any
	switch block.Type {
	case "PRIVATE KEY":
		keyAny, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		keyAny, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("expected PRIVATE KEY or EC PRIVATE KEY block, got %q", block.Type)
	}
	if err != nil {
		return nil, err
	}
	priv, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not ECDSA (got %T)", keyAny)
	}
	if priv.Curve != elliptic.P256() {
		return nil, fmt.Errorf("key is not P-256 (got %s)", priv.Curve.Params().Name)
	}
	return priv, nil
}
