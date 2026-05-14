#!/usr/bin/env bash
#
# build-tarball.sh — assemble the tesseract-proxy release tarball.
#
# Output:
#   <out>/tesseract-proxy-<version>-linux-<arch>.tar.gz
#   <out>/tesseract-proxy-<version>-linux-<arch>.tar.gz.sha256
#
# Tarball layout:
#   bin/proxy                                 cross-compiled linux/<arch>
#   bin/proxy.sig                             ECDSA P-256 DER over SHA-256(proxy)
#   bin/tesseract-proxy-egress                companion binary, optional
#   etc/profiles/bundle.yaml                  signed broker bundle
#   etc/profiles/bundle.yaml.sig              ECDSA P-256 DER over SHA-256(bundle)
#   etc/pubkey/equinomics-signing.pub         PKIX PEM ECDSA P-256 pubkey
#   etc/proxy.conf.yaml.template              starter operator config
#   systemd/tesseract-proxy.service           hardened systemd unit
#   deploy/cfn.yaml                           CloudFormation template
#   scripts/gen-mtls.sh                       mTLS chain regenerator
#   install.sh                                operator-facing installer
#   README.md                                 deploy walkthrough
#
# Usage:
#   ./build-tarball.sh \
#       --version v0.2.0 \
#       --signer-key <path> \
#       [--pubkey <path>]   \
#       [--arch amd64|arm64] \
#       [--skip-egress] \
#       [--out <dir>]
#
# Defaults:
#   --signer-key = releases/keys/signing.key
#   --pubkey     = <signer-key>.pub  (signing.key → signing.pub fallback also tried)
#   --arch       = amd64
#   --out        = /tmp
#
# Signing scheme (matches internal/profile and internal/binupd verify):
#   sig = openssl dgst -sha256 -sign signing.key -out f.sig f
# Verification (in-tarball install.sh and the proxy itself):
#   openssl dgst -sha256 -verify signing.pub -signature f.sig f

set -euo pipefail

VERSION=""
SIGNER_KEY=""
PUBKEY=""
SKIP_EGRESS=0
OUT_DIR="/tmp"
ARCH="amd64"

while [ $# -gt 0 ]; do
    case "$1" in
        --version)     VERSION="$2"; shift 2 ;;
        --signer-key)  SIGNER_KEY="$2"; shift 2 ;;
        --pubkey)      PUBKEY="$2"; shift 2 ;;
        --skip-egress) SKIP_EGRESS=1; shift ;;
        --arch)        ARCH="$2"; shift 2 ;;
        --out)         OUT_DIR="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
done

case "$ARCH" in
    amd64|arm64) ;;
    *) echo "--arch must be amd64 or arm64 (got: $ARCH)" >&2; exit 1 ;;
esac

[ -n "$VERSION" ] || { echo "--version is required (e.g. v0.2.0)" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
SRC_ROOT="$REPO_ROOT/src"

# Defaults that point at the keys gen-signing-key.sh wrote.
[ -n "$SIGNER_KEY" ] || SIGNER_KEY="$REPO_ROOT/releases/keys/signing.key"
[ -f "$SIGNER_KEY" ] || { echo "signer key not found: $SIGNER_KEY  (run gen-signing-key.sh first)" >&2; exit 1; }

if [ -z "$PUBKEY" ]; then
    # Prefer the conventional sibling name.
    if   [ -f "${SIGNER_KEY%.key}.pub" ]; then PUBKEY="${SIGNER_KEY%.key}.pub"
    elif [ -f "${SIGNER_KEY}.pub" ];       then PUBKEY="${SIGNER_KEY}.pub"
    fi
fi
[ -n "$PUBKEY" ] && [ -f "$PUBKEY" ] || { echo "pubkey not found (--pubkey or alongside signer key)" >&2; exit 1; }

# Absolutize.
SIGNER_KEY="$(cd "$(dirname "$SIGNER_KEY")" && pwd)/$(basename "$SIGNER_KEY")"
PUBKEY="$(cd "$(dirname "$PUBKEY")" && pwd)/$(basename "$PUBKEY")"

PROXY_DIR="$SRC_ROOT/tesseract-proxy"
EGRESS_DIR="$SRC_ROOT/tesseract-proxy-egress"
CONFIG_DIR="$SRC_ROOT/tesseract-proxy-config"
RELEASE_DIR="$SRC_ROOT/release"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

STAGE="$WORK/tesseract-proxy-$VERSION-linux-$ARCH"
mkdir -p "$STAGE"/{bin,etc/profiles,etc/pubkey,systemd,deploy,scripts}

echo "==> cross-compiling proxy ($VERSION) → linux/$ARCH"
( cd "$PROXY_DIR" && \
  GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 \
  go build -ldflags "-s -w -X main.Version=$VERSION" \
      -o "$STAGE/bin/proxy" ./cmd/proxy )

echo "==> signing proxy binary (ECDSA P-256 / SHA-256)"
openssl dgst -sha256 -sign "$SIGNER_KEY" -out "$STAGE/bin/proxy.sig" "$STAGE/bin/proxy"

if [ "$SKIP_EGRESS" -eq 0 ] && [ -d "$EGRESS_DIR" ]; then
    echo "==> cross-compiling tesseract-proxy-egress → linux/$ARCH"
    ( cd "$EGRESS_DIR" && \
      GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 \
      go build -ldflags "-s -w" \
          -o "$STAGE/bin/tesseract-proxy-egress" . )
fi

echo "==> building bundle from $CONFIG_DIR"
( cd "$PROXY_DIR" && \
  go run ./cmd/build-bundle \
      -meta "$CONFIG_DIR/meta.yaml" \
      -brokers "$CONFIG_DIR/brokers" \
      -out "$WORK/bundle.yaml" \
      -sig "$WORK/bundle.yaml.sig" \
      -signer-key "$SIGNER_KEY" \
      -bundle-version "$VERSION" )

cp "$WORK/bundle.yaml"      "$STAGE/etc/profiles/bundle.yaml"
cp "$WORK/bundle.yaml.sig"  "$STAGE/etc/profiles/bundle.yaml.sig"
cp "$PUBKEY"                "$STAGE/etc/pubkey/equinomics-signing.pub"

cp "$RELEASE_DIR/deploy/tesseract-proxy.service"   "$STAGE/systemd/"
cp "$RELEASE_DIR/deploy/cfn.yaml"                  "$STAGE/deploy/cfn.yaml"
cp "$RELEASE_DIR/scripts/gen-mtls.sh"              "$STAGE/scripts/gen-mtls.sh"
cp "$RELEASE_DIR/install.sh"                       "$STAGE/install.sh"
cp "$RELEASE_DIR/proxy.conf.yaml.template"         "$STAGE/etc/proxy.conf.yaml.template"
cp "$RELEASE_DIR/README.md"                        "$STAGE/README.md"
chmod +x "$STAGE/install.sh" "$STAGE/scripts/gen-mtls.sh"

mkdir -p "$OUT_DIR"
TARBALL="$OUT_DIR/tesseract-proxy-$VERSION-linux-$ARCH.tar.gz"
echo "==> tarring → $TARBALL"
tar -C "$WORK" -czf "$TARBALL" "tesseract-proxy-$VERSION-linux-$ARCH"

SHA=$(sha256sum "$TARBALL" | awk '{print $1}')
echo "$SHA  $(basename "$TARBALL")" > "${TARBALL}.sha256"

echo
echo "release built:"
echo "  $TARBALL"
echo "  ${TARBALL}.sha256"
echo "  sha256: $SHA"
