#!/usr/bin/env bash
#
# Build the tesseract-proxy release tarball:
#
#   tesseract-proxy-<version>-linux-arm64.tar.gz
#
# Layout inside the tarball:
#   bin/proxy                                  (cross-compiled linux/arm64)
#   bin/proxy.sig                              (Ed25519 detached signature)
#   bin/tesseract-proxy-egress                 (companion binary, optional)
#   etc/profiles/bundle.yaml                   (signed broker bundle)
#   etc/profiles/bundle.yaml.sig               (Ed25519 detached signature)
#   etc/pubkey/equinomics-signing.pub          (PEM PKIX Ed25519 pubkey)
#   etc/proxy.conf.yaml.template               (starter operator config)
#   systemd/tesseract-proxy.service            (hardened systemd unit)
#   install.sh                                 (operator-facing installer)
#   README.md                                  (deploy walkthrough)
#
# Usage:
#   ./build-release.sh \
#       --version v0.1.0 \
#       --signer-key /path/to/ed25519.key \
#       [--pubkey /path/to/ed25519.key.pub] \
#       [--bundle /path/to/bundle.yaml] \
#       [--bundle-sig /path/to/bundle.yaml.sig] \
#       [--skip-egress] \
#       [--out /tmp/releases]
#
# Defaults:
#   --pubkey      = <signer-key>.pub
#   --bundle      = tesseract-proxy-config/bundle.yaml (built if missing)
#   --bundle-sig  = <bundle>.sig
#   --out         = /tmp
#
# Exit non-zero on any failure. No partial tarballs left behind.

set -euo pipefail

VERSION=""
SIGNER_KEY=""
PUBKEY=""
BUNDLE=""
BUNDLE_SIG=""
SKIP_EGRESS=0
OUT_DIR="/tmp"

while [ $# -gt 0 ]; do
    case "$1" in
        --version)     VERSION="$2"; shift 2 ;;
        --signer-key)  SIGNER_KEY="$2"; shift 2 ;;
        --pubkey)      PUBKEY="$2"; shift 2 ;;
        --bundle)      BUNDLE="$2"; shift 2 ;;
        --bundle-sig)  BUNDLE_SIG="$2"; shift 2 ;;
        --skip-egress) SKIP_EGRESS=1; shift ;;
        --out)         OUT_DIR="$2"; shift 2 ;;
        *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
done

[ -n "$VERSION" ]    || { echo "--version is required (e.g. v0.1.0)" >&2; exit 1; }
[ -n "$SIGNER_KEY" ] || { echo "--signer-key is required" >&2; exit 1; }
[ -f "$SIGNER_KEY" ] || { echo "signer key not found: $SIGNER_KEY" >&2; exit 1; }

[ -n "$PUBKEY" ] || PUBKEY="${SIGNER_KEY}.pub"
[ -f "$PUBKEY" ] || { echo "pubkey not found: $PUBKEY (override with --pubkey)" >&2; exit 1; }

SRC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # src/
PROXY_DIR="$SRC_ROOT/tesseract-proxy"
EGRESS_DIR="$SRC_ROOT/tesseract-proxy-egress"
CONFIG_DIR="$SRC_ROOT/tesseract-proxy-config"
BUILD_BUNDLE_DIR="$SRC_ROOT/BuildScripts/build-bundle"
RELEASE_DIR="$SRC_ROOT/release"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

STAGE="$WORK/tesseract-proxy-$VERSION-linux-arm64"
mkdir -p "$STAGE"/{bin,etc/profiles,etc/pubkey,systemd}

echo "==> cross-compiling proxy ($VERSION) → linux/arm64"
( cd "$PROXY_DIR" && \
  GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
  go build -ldflags "-s -w -X main.Version=$VERSION" \
      -o "$STAGE/bin/proxy" ./cmd/proxy )

echo "==> signing proxy binary"
openssl pkeyutl -sign -inkey "$SIGNER_KEY" -rawin -in "$STAGE/bin/proxy" \
    -out "$STAGE/bin/proxy.sig"

if [ "$SKIP_EGRESS" -eq 0 ] && [ -d "$EGRESS_DIR" ]; then
    echo "==> cross-compiling tesseract-proxy-egress → linux/arm64"
    ( cd "$EGRESS_DIR" && \
      GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
      go build -ldflags "-s -w" \
          -o "$STAGE/bin/tesseract-proxy-egress" . )
fi

# Build bundle from tesseract-proxy-config/ if --bundle not passed.
if [ -z "$BUNDLE" ]; then
    if [ ! -d "$CONFIG_DIR" ]; then
        echo "tesseract-proxy-config/ not found; pass --bundle to override" >&2
        exit 1
    fi
    echo "==> building bundle from $CONFIG_DIR"
    ( cd "$BUILD_BUNDLE_DIR" && \
      go run . \
          -meta "$CONFIG_DIR/meta.yaml" \
          -brokers "$CONFIG_DIR/brokers" \
          -out "$WORK/bundle.yaml" \
          -sig "$WORK/bundle.yaml.sig" \
          -signer-key "$SIGNER_KEY" \
          -bundle-version "$VERSION" )
    BUNDLE="$WORK/bundle.yaml"
    BUNDLE_SIG="$WORK/bundle.yaml.sig"
fi
[ -n "$BUNDLE_SIG" ] || BUNDLE_SIG="${BUNDLE}.sig"
[ -f "$BUNDLE" ]     || { echo "bundle not found: $BUNDLE" >&2; exit 1; }
[ -f "$BUNDLE_SIG" ] || { echo "bundle sig not found: $BUNDLE_SIG" >&2; exit 1; }

cp "$BUNDLE"     "$STAGE/etc/profiles/bundle.yaml"
cp "$BUNDLE_SIG" "$STAGE/etc/profiles/bundle.yaml.sig"
cp "$PUBKEY"     "$STAGE/etc/pubkey/equinomics-signing.pub"

cp "$RELEASE_DIR/deploy/tesseract-proxy.service" "$STAGE/systemd/"
cp "$RELEASE_DIR/install.sh"                     "$STAGE/install.sh"
cp "$RELEASE_DIR/proxy.conf.yaml.template"       "$STAGE/etc/proxy.conf.yaml.template"
cp "$RELEASE_DIR/README.md"                      "$STAGE/README.md"
chmod +x "$STAGE/install.sh"

TARBALL="$OUT_DIR/tesseract-proxy-$VERSION-linux-arm64.tar.gz"
echo "==> tarring → $TARBALL"
tar -C "$WORK" -czf "$TARBALL" "tesseract-proxy-$VERSION-linux-arm64"

SHA=$(sha256sum "$TARBALL" | awk '{print $1}')
echo "$SHA  $(basename "$TARBALL")" > "${TARBALL}.sha256"

echo
echo "release built:"
echo "  $TARBALL"
echo "  ${TARBALL}.sha256"
echo "  sha256: $SHA"
