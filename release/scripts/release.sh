#!/usr/bin/env bash
#
# release.sh — orchestrator for a clean tesseract-proxy release.
#
# Wraps gen-signing-key.sh → gen-mtls.sh → build-tarball.sh → deploy-lightsail.sh
# (or just build-tarball.sh, if --no-deploy). Single command:
#
#   ./release.sh --version v0.2.0 --lightsail-ip 13.207.35.97
#
# Behaviour:
#   - Signing key is generated only if releases/keys/signing.{key,pub} is missing.
#     Re-use across versions is intentional: the public key is pinned at
#     install time on every box; rotating it requires a coordinated redeploy.
#   - mTLS material is generated only if releases/mtls/ca.{pem,key} is missing.
#     For subsequent client re-issues, run gen-mtls.sh --reuse-server directly;
#     this orchestrator does not auto-rotate certs.
#   - Tarball is rebuilt every run (versioned name; old tarballs kept).
#   - Deploy step picks first-time provision (deploy-lightsail.sh) vs
#     in-place update (update-lightsail.sh) by checking whether the
#     Lightsail instance already exists.
#
# Usage:
#   ./release.sh \
#       --version v0.2.0 \
#       --lightsail-ip 13.207.35.97 \
#       [--arch amd64|arm64] \
#       [--region ap-south-1] \
#       [--ssh-key <path>] \
#       [--key-pair <lightsail-keypair-name>] \
#       [--no-deploy]                # build tarball only
#
# What it does NOT do:
#   - Open ports it didn't open (deploy-lightsail.sh handles that).
#   - Edit /etc/tesseract-proxy/proxy.conf.yaml on running boxes (that's
#     reload-bundle.sh territory + the admin UI in R6).
#   - Rotate mTLS material. Use gen-mtls.sh --reuse-server explicitly.

set -euo pipefail

VERSION=""
LIGHTSAIL_IP=""
ARCH="amd64"
REGION="ap-south-1"
SSH_KEY=""
KEY_PAIR=""
INSTANCE_NAME="tesseract-proxy"
NO_DEPLOY=0

while [ $# -gt 0 ]; do
    case "$1" in
        --version)        VERSION="$2"; shift 2 ;;
        --lightsail-ip)   LIGHTSAIL_IP="$2"; shift 2 ;;
        --arch)           ARCH="$2"; shift 2 ;;
        --region)         REGION="$2"; shift 2 ;;
        --ssh-key)        SSH_KEY="$2"; shift 2 ;;
        --key-pair)       KEY_PAIR="$2"; shift 2 ;;
        --instance-name)  INSTANCE_NAME="$2"; shift 2 ;;
        --no-deploy)      NO_DEPLOY=1; shift ;;
        -h|--help)
            sed -n '2,38p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
done

[ -n "$VERSION" ] || { echo "--version is required (e.g. v0.2.0)" >&2; exit 1; }
if [ "$NO_DEPLOY" -eq 0 ]; then
    [ -n "$LIGHTSAIL_IP" ] || { echo "--lightsail-ip is required (or pass --no-deploy)" >&2; exit 1; }
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
KEYS_DIR="$REPO_ROOT/releases/keys"
MTLS_DIR="$REPO_ROOT/releases/mtls"

# --- 1. Signing key ---------------------------------------------------------
if [ ! -f "$KEYS_DIR/signing.key" ]; then
    echo "==> [1/4] generating ECDSA P-256 signing keypair"
    bash "$SCRIPT_DIR/gen-signing-key.sh" --out "$KEYS_DIR"
else
    echo "==> [1/4] signing key exists; reusing $KEYS_DIR/signing.key"
fi

# --- 2. mTLS material -------------------------------------------------------
if [ ! -f "$MTLS_DIR/ca.pem" ]; then
    echo "==> [2/4] generating ECDSA P-256 mTLS chain"
    if [ "$NO_DEPLOY" -eq 1 ] || [ -z "$LIGHTSAIL_IP" ]; then
        echo "    skipping mTLS gen (--no-deploy and/or no --lightsail-ip); run gen-mtls.sh separately"
    else
        bash "$SCRIPT_DIR/gen-mtls.sh" \
            --lightsail-ip "$LIGHTSAIL_IP" \
            --out "$MTLS_DIR"
    fi
else
    echo "==> [2/4] mTLS material exists; reusing $MTLS_DIR/"
fi

# --- 3. Tarball -------------------------------------------------------------
echo "==> [3/4] building tarball $VERSION ($ARCH)"
bash "$SCRIPT_DIR/build-tarball.sh" \
    --version "$VERSION" \
    --arch "$ARCH" \
    --out "$REPO_ROOT/releases"
TARBALL="$REPO_ROOT/releases/tesseract-proxy-$VERSION-linux-$ARCH.tar.gz"

# --- 4. Deploy --------------------------------------------------------------
if [ "$NO_DEPLOY" -eq 1 ]; then
    echo "==> [4/4] --no-deploy; tarball ready at $TARBALL"
    exit 0
fi

CLIENT_SERIAL=""
if [ -f "$MTLS_DIR/client.pem" ]; then
    ACTUAL_HEX=$(openssl x509 -in "$MTLS_DIR/client.pem" -noout -serial | sed 's/serial=//' | tr 'A-F' 'a-f')
    CLIENT_SERIAL=$(printf '%d\n' "0x$ACTUAL_HEX")
fi

EXTRA_ARGS=()
[ -n "$SSH_KEY" ]  && EXTRA_ARGS+=(--ssh-key "$SSH_KEY")
[ -n "$KEY_PAIR" ] && EXTRA_ARGS+=(--key-pair "$KEY_PAIR")

# Decide first-time vs update by asking AWS whether the instance exists.
INSTANCE_EXISTS=0
if command -v aws >/dev/null 2>&1; then
    if aws --region "$REGION" lightsail get-instance \
        --instance-name "$INSTANCE_NAME" >/dev/null 2>&1; then
        INSTANCE_EXISTS=1
    fi
fi

if [ "$INSTANCE_EXISTS" -eq 1 ]; then
    echo "==> [4/4] instance '$INSTANCE_NAME' exists → in-place update"
    bash "$SCRIPT_DIR/update-lightsail.sh" \
        --tarball "$TARBALL" \
        --lightsail-ip "$LIGHTSAIL_IP" \
        --instance-name "$INSTANCE_NAME" \
        --region "$REGION" \
        "${EXTRA_ARGS[@]}"
else
    [ -n "$CLIENT_SERIAL" ] || { echo "first-time deploy needs a client cert (mTLS_DIR=$MTLS_DIR); run gen-mtls.sh first" >&2; exit 1; }
    echo "==> [4/4] first-time provision via deploy-lightsail.sh"
    bash "$SCRIPT_DIR/deploy-lightsail.sh" \
        --tarball "$TARBALL" \
        --mtls-dir "$MTLS_DIR" \
        --client-serial "$CLIENT_SERIAL" \
        --instance-name "$INSTANCE_NAME" \
        --region "$REGION" \
        "${EXTRA_ARGS[@]}"
fi

echo
echo "==> release.sh done. version=$VERSION ip=$LIGHTSAIL_IP"
