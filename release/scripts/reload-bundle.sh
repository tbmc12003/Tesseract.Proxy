#!/usr/bin/env bash
#
# reload-bundle.sh — push a freshly-built signed broker bundle to a running
# tesseract-proxy and SIGHUP it. No binary swap, no service restart.
#
# This is the hot path the local admin UI (R6) uses after the operator
# edits broker config and clicks "Publish".
#
# Flow:
#   1. Verify the bundle signature locally against signing.pub (cheap
#      pre-flight; the proxy re-verifies before swapping in).
#   2. SCP bundle.yaml + bundle.yaml.sig to /tmp on the box.
#   3. Atomically install both files into /etc/tesseract-proxy/profiles/.
#   4. `systemctl reload tesseract-proxy` — proxy re-reads, verifies,
#      validates schema + monotonic version, and hot-swaps the router on
#      success. On failure the previous router stays live (the proxy's
#      load is all-or-nothing).
#
# Usage:
#   ./reload-bundle.sh \
#       --bundle <bundle.yaml> \
#       --sig    <bundle.yaml.sig> \
#       --lightsail-ip <ip> \
#       [--pubkey <signing.pub>] \
#       [--ssh-key <path>]
#
# Defaults:
#   --pubkey = releases/keys/signing.pub

set -euo pipefail

BUNDLE=""
SIG=""
IP=""
PUBKEY=""
SSH_KEY=""

while [ $# -gt 0 ]; do
    case "$1" in
        --bundle)         BUNDLE="$2"; shift 2 ;;
        --sig)            SIG="$2"; shift 2 ;;
        --lightsail-ip)   IP="$2"; shift 2 ;;
        --pubkey)         PUBKEY="$2"; shift 2 ;;
        --ssh-key)        SSH_KEY="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

[ -n "$IP" ]     || { echo "--lightsail-ip is required" >&2; exit 1; }
[ -n "$BUNDLE" ] || { echo "--bundle is required" >&2; exit 1; }
[ -n "$SIG" ]    || { echo "--sig is required" >&2; exit 1; }
[ -f "$BUNDLE" ] || { echo "bundle not found: $BUNDLE" >&2; exit 1; }
[ -f "$SIG" ]    || { echo "sig not found: $SIG" >&2; exit 1; }

[ -n "$PUBKEY" ] || PUBKEY="$REPO_ROOT/releases/keys/signing.pub"
[ -f "$PUBKEY" ] || { echo "pubkey not found: $PUBKEY (run gen-signing-key.sh)" >&2; exit 1; }

echo "==> local sig verify (ECDSA P-256 / SHA-256)"
openssl dgst -sha256 -verify "$PUBKEY" -signature "$SIG" "$BUNDLE" >/dev/null

SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
[ -n "$SSH_KEY" ] && SSH_OPTS+=(-i "$SSH_KEY")

echo "==> uploading bundle to $IP"
scp "${SSH_OPTS[@]}" "$BUNDLE" "$SIG" ec2-user@"$IP":/tmp/

REMOTE_BUNDLE="/tmp/$(basename "$BUNDLE")"
REMOTE_SIG="/tmp/$(basename "$SIG")"

echo "==> installing + reloading"
ssh "${SSH_OPTS[@]}" ec2-user@"$IP" bash <<REMOTE
set -euo pipefail
sudo install -o root -g tesseract-proxy -m 0640 \
    "$REMOTE_BUNDLE" /etc/tesseract-proxy/profiles/bundle.yaml
sudo install -o root -g tesseract-proxy -m 0640 \
    "$REMOTE_SIG" /etc/tesseract-proxy/profiles/bundle.yaml.sig
rm -f "$REMOTE_BUNDLE" "$REMOTE_SIG"
sudo systemctl reload tesseract-proxy
sleep 1
sudo journalctl -u tesseract-proxy -n 20 --no-pager
REMOTE

cat <<DONE

==> bundle reload complete.
  Bundle: $(basename "$BUNDLE")  ($(wc -c < "$BUNDLE") bytes)
  Host:   ec2-user@$IP

Confirm the swap took:
  ssh${SSH_KEY:+ -i $SSH_KEY} ec2-user@$IP sudo journalctl -u tesseract-proxy -n 5 --no-pager
Expect: a "bundle swapped" line with the new bundle_version, no "verify failed".

DONE
