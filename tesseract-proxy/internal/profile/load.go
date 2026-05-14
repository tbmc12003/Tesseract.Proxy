package profile

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadOptions configures a load + verify operation.
type LoadOptions struct {
	// BundlePath is the path to the bundle YAML file.
	BundlePath string
	// SigPath is the path to the detached ECDSA P-256 signature (ASN.1 DER,
	// as produced by `openssl dgst -sha256 -sign` or Go's ecdsa.SignASN1).
	SigPath string
	// PubkeyPath is the path to a PEM-encoded PKIX ECDSA P-256 public key.
	PubkeyPath string
	// BinaryVersion is the running proxy version; if non-empty and
	// non-"dev", the bundle's min_proxy_version is enforced against it.
	BinaryVersion string
	// PreviousBundleVersion, if non-empty, gates monotonic downgrades:
	// the new bundle_version must compare strictly greater (lex order) to
	// the previous, or the load is refused.
	PreviousBundleVersion string
}

// Result is the output of a successful LoadAndVerify.
type Result struct {
	Bundle *Bundle
	Router *Router
}

// LoadAndVerify reads the bundle, verifies its detached signature against
// the pinned pubkey, validates the schema, enforces version gates, and
// returns an immutable Router.
//
// All-or-nothing: any failure leaves no Router behind. Callers that hold a
// previously-loaded Router should retain it and only swap on success.
func LoadAndVerify(opts LoadOptions) (*Result, error) {
	bundleBytes, err := os.ReadFile(opts.BundlePath)
	if err != nil {
		return nil, fmt.Errorf("profile: read bundle: %w", err)
	}
	sigBytes, err := os.ReadFile(opts.SigPath)
	if err != nil {
		return nil, fmt.Errorf("profile: read signature: %w", err)
	}
	pub, err := readPubkey(opts.PubkeyPath)
	if err != nil {
		return nil, err
	}

	if err := verifySignature(pub, bundleBytes, sigBytes); err != nil {
		return nil, err
	}

	b, err := decodeBundle(bundleBytes)
	if err != nil {
		return nil, err
	}

	if err := b.validate(); err != nil {
		return nil, err
	}

	if err := enforceVersionGates(b, opts); err != nil {
		return nil, err
	}

	r, err := b.buildRouter()
	if err != nil {
		return nil, err
	}

	return &Result{Bundle: b, Router: r}, nil
}

func decodeBundle(data []byte) (*Bundle, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var b Bundle
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("profile: parse yaml: %w", err)
	}
	var tail any
	if err := dec.Decode(&tail); err == nil {
		return nil, fmt.Errorf("profile: parse yaml: unexpected additional document")
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("profile: parse yaml (trailing): %w", err)
	}
	return &b, nil
}

func readPubkey(path string) (*ecdsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("profile: read pubkey: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("profile: pubkey: no PEM block in %s", path)
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("profile: pubkey: unexpected PEM type %q (want PUBLIC KEY)", block.Type)
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("profile: pubkey: parse PKIX: %w", err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("profile: pubkey: not an ECDSA key (got %T)", pubAny)
	}
	if pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("profile: pubkey: expected P-256, got %s", pub.Curve.Params().Name)
	}
	return pub, nil
}

func verifySignature(pub *ecdsa.PublicKey, msg, sig []byte) error {
	if len(sig) == 0 {
		return errors.New("profile: signature: empty")
	}
	h := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(pub, h[:], sig) {
		return errors.New("profile: signature: verification failed")
	}
	return nil
}

func enforceVersionGates(b *Bundle, opts LoadOptions) error {
	// min_proxy_version vs running binary
	if opts.BinaryVersion != "" && opts.BinaryVersion != "dev" {
		cmp, err := compareSemver(opts.BinaryVersion, b.MinProxyVersion)
		if err != nil {
			return fmt.Errorf("profile: version gate: %w", err)
		}
		if cmp < 0 {
			return fmt.Errorf("profile: min_proxy_version %s exceeds binary version %s",
				b.MinProxyVersion, opts.BinaryVersion)
		}
	}

	// monotonic bundle_version
	if opts.PreviousBundleVersion != "" {
		if b.BundleVersion <= opts.PreviousBundleVersion {
			return fmt.Errorf("profile: downgrade refused: bundle_version %q is not strictly greater than previous %q",
				b.BundleVersion, opts.PreviousBundleVersion)
		}
	}
	return nil
}

// compareSemver returns -1 / 0 / 1 if a < b / a == b / a > b. Both inputs
// must be of the form "MAJOR.MINOR.PATCH" with optional leading "v".
// Pre-release / build metadata is not currently supported — we'd add it
// when the bundle starts emitting "1.0.0-rc1"-style strings.
func compareSemver(a, b string) (int, error) {
	aParts, err := parseSemver(a)
	if err != nil {
		return 0, err
	}
	bParts, err := parseSemver(b)
	if err != nil {
		return 0, err
	}
	for i := 0; i < 3; i++ {
		if aParts[i] < bParts[i] {
			return -1, nil
		}
		if aParts[i] > bParts[i] {
			return 1, nil
		}
	}
	return 0, nil
}

func parseSemver(s string) ([3]int, error) {
	s = strings.TrimPrefix(s, "v")
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return [3]int{}, fmt.Errorf("invalid semver %q (want MAJOR.MINOR.PATCH)", s)
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [3]int{}, fmt.Errorf("invalid semver component %q in %q", p, s)
		}
		out[i] = n
	}
	return out, nil
}
