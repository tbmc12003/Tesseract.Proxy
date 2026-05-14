#!/usr/bin/env bash
#
# gen-signing-key.sh — generate the ECDSA P-256 signing keypair used to sign
# the proxy binary and the broker bundle.
#
# Output:
#   <out>/signing.key   ECDSA P-256, PKCS#8 PEM, mode 0600
#   <out>/signing.pub   PKIX PEM public key
#
# Defaults:
#   --out  = releases/keys
#
# Usage:
#   ./gen-signing-key.sh [--out <dir>] [--force]
#
# Idempotent: refuses to overwrite an existing key unless --force is given.
# The public key is committed; the private key is gitignored.
#
# Why ECDSA P-256:
#   First-class in .NET (System.Security.Cryptography.ECDsa), Go
#   (crypto/ecdsa), and OpenSSL. Replaces the legacy Ed25519 signing key,
#   which works in Go but is rejected by .NET/Schannel for cert use and
#   keeps the trust story bifurcated. One algorithm everywhere is simpler.

set -euo pipefail

OUT_DIR=""
FORCE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --out)   OUT_DIR="$2"; shift 2 ;;
        --force) FORCE=1; shift ;;
        -h|--help)
            sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
[ -n "$OUT_DIR" ] || OUT_DIR="$REPO_ROOT/releases/keys"

mkdir -p "$OUT_DIR"
KEY="$OUT_DIR/signing.key"
PUB="$OUT_DIR/signing.pub"

if [ -e "$KEY" ] || [ -e "$PUB" ]; then
    if [ "$FORCE" -ne 1 ]; then
        echo "signing key already exists at $OUT_DIR" >&2
        echo "  $KEY" >&2
        echo "  $PUB" >&2
        echo "pass --force to overwrite (this invalidates every artifact previously signed with the old key)" >&2
        exit 1
    fi
    rm -f "$KEY" "$PUB"
fi

echo "==> generating ECDSA P-256 signing keypair → $OUT_DIR"

# Private key: PKCS#8 PEM. -pkeyopt ec_paramgen_curve:P-256 forces P-256.
openssl genpkey \
    -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 \
    -pkeyopt ec_param_enc:named_curve \
    -out "$KEY"
chmod 0600 "$KEY"

# Public key: PKIX PEM. Matches what the proxy expects in
# etc/pubkey/equinomics-signing.pub (loaded by internal/profile/load.go).
openssl pkey -in "$KEY" -pubout -out "$PUB"
chmod 0644 "$PUB"

# Sanity check: round-trip a sign+verify so we fail loudly here, not at
# release time.
TMP=$(mktemp)
trap 'rm -f "$TMP" "$TMP.sig"' EXIT
echo "signing-key-self-test" > "$TMP"
openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$TMP" -out "$TMP.sig" \
    -digestout sha256 >/dev/null 2>&1 || \
    openssl dgst -sha256 -sign "$KEY" -out "$TMP.sig" "$TMP"
openssl dgst -sha256 -verify "$PUB" -signature "$TMP.sig" "$TMP" >/dev/null

echo "==> done"
echo "  private: $KEY  (mode 0600 — do not commit)"
echo "  public : $PUB"
echo
echo "next: ./gen-mtls.sh to mint the mTLS chain, then ./release.sh."
