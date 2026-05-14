#!/usr/bin/env bash
#
# update-lightsail.sh — push a new tarball to an existing tesseract-proxy
# Lightsail instance. Used for proxy version bumps and bundle refreshes
# that travel with a new binary.
#
# Flow:
#   1. Verify the local tarball + .sha256.
#   2. SCP tarball to the box.
#   3. Untar, sha256-verify on-box, run install.sh.
#      install.sh is idempotent: keeps /etc/tesseract-proxy/* and certs
#      untouched; replaces /opt/tesseract-proxy/proxy + systemd unit +
#      shipped bundle + pubkey.
#   4. `systemctl restart tesseract-proxy` (NOT reload — binary changed).
#   5. Optionally close inbound 22 after install (`--close-ssh`).
#
# Usage:
#   ./update-lightsail.sh \
#       --tarball <path> \
#       --lightsail-ip <ip> \
#       [--ssh-key <path>] \
#       [--close-ssh]
#
# Defaults:
#   --tarball = newest releases/tesseract-proxy-*.tar.gz

set -euo pipefail

TARBALL=""
IP=""
SSH_KEY=""
CLOSE_SSH=0
INSTANCE_NAME="tesseract-proxy"
REGION="ap-south-1"

while [ $# -gt 0 ]; do
    case "$1" in
        --tarball)        TARBALL="$2"; shift 2 ;;
        --lightsail-ip)   IP="$2"; shift 2 ;;
        --ssh-key)        SSH_KEY="$2"; shift 2 ;;
        --instance-name)  INSTANCE_NAME="$2"; shift 2 ;;
        --region)         REGION="$2"; shift 2 ;;
        --close-ssh)      CLOSE_SSH=1; shift ;;
        -h|--help)
            sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

[ -n "$IP" ] || { echo "--lightsail-ip is required" >&2; exit 1; }

if [ -z "$TARBALL" ]; then
    TARBALL=$(ls -t "$REPO_ROOT/releases/"tesseract-proxy-*.tar.gz 2>/dev/null | head -1 || true)
fi
[ -f "$TARBALL" ] || { echo "tarball not found: $TARBALL" >&2; exit 1; }

SHA_FILE="${TARBALL}.sha256"
[ -f "$SHA_FILE" ] || { echo ".sha256 sidecar not found: $SHA_FILE  (rebuild via build-tarball.sh)" >&2; exit 1; }

echo "==> local sha256 verify"
( cd "$(dirname "$TARBALL")" && sha256sum -c "$(basename "$SHA_FILE")" )

SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
[ -n "$SSH_KEY" ] && SSH_OPTS+=(-i "$SSH_KEY")

echo "==> uploading tarball to $IP"
scp "${SSH_OPTS[@]}" "$TARBALL" "$SHA_FILE" ec2-user@"$IP":~/

TARBALL_BASENAME=$(basename "$TARBALL")
SHA_BASENAME=$(basename "$SHA_FILE")
TARBALL_STEM="${TARBALL_BASENAME%.tar.gz}"

echo "==> verifying + installing on $IP"
ssh "${SSH_OPTS[@]}" ec2-user@"$IP" bash <<REMOTE
set -euo pipefail
sha256sum -c "$SHA_BASENAME"
tar xzf "$TARBALL_BASENAME"
sudo "./$TARBALL_STEM/install.sh"
sudo systemctl restart tesseract-proxy
sudo systemctl status tesseract-proxy --no-pager | head -20

rm -rf "$TARBALL_STEM" "$TARBALL_BASENAME" "$SHA_BASENAME"
REMOTE

if [ "$CLOSE_SSH" -eq 1 ]; then
    command -v aws >/dev/null 2>&1 || { echo "--close-ssh needs the aws CLI" >&2; exit 1; }
    echo "==> closing inbound 22 on $INSTANCE_NAME ($REGION)"
    aws --region "$REGION" lightsail close-instance-public-ports \
        --instance-name "$INSTANCE_NAME" \
        --port-info "fromPort=22,toPort=22,protocol=tcp" >/dev/null
    echo "    SSH is now closed. To reopen: aws lightsail open-instance-public-ports ..."
fi

cat <<DONE

==> update complete.
  Tarball: $TARBALL_BASENAME
  Host:    ec2-user@$IP

Tail logs:
  ssh${SSH_KEY:+ -i $SSH_KEY} ec2-user@$IP sudo journalctl -u tesseract-proxy -f
DONE
