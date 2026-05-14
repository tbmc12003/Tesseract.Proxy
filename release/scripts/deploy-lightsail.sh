#!/usr/bin/env bash
#
# deploy-lightsail.sh — first-time provision of tesseract-proxy on AWS Lightsail.
#
# What it does (idempotent — safe to re-run):
#   1. Creates a Lightsail instance (Amazon Linux 2023) if one with the
#      same name doesn't already exist.
#   2. Allocates + attaches a static IP (kept on stack-retain semantics).
#   3. Opens inbound TCP 22 + 443 (22 closeable after install via
#      `update-lightsail.sh --close-ssh`).
#   4. Waits until SSH is reachable.
#   5. SCPs the release tarball + mTLS server material to the box.
#   6. Runs install.sh remotely (verifies signatures + lays out systemd).
#   7. SCPs proxy.conf.yaml (templated with allowed serials from gen-mtls).
#   8. Enables and starts the systemd unit.
#   9. Prints the static IP for broker whitelisting + a tail-the-logs hint.
#
# Usage:
#   ./deploy-lightsail.sh \
#       --tarball  <path>      \
#       --mtls-dir <path>      \
#       --client-serial <int>  \
#       [--instance-name tesseract-proxy] \
#       [--region ap-south-1] \
#       [--availability-zone ap-south-1a] \
#       [--bundle nano_3_1] \
#       [--key-pair <lightsail-key-pair-name>] \
#       [--ssh-key  <local-ssh-private-key-path>] \
#       [--allowed-cidr 0.0.0.0/0]
#
# Defaults:
#   --tarball         = newest releases/tesseract-proxy-*.tar.gz
#   --mtls-dir        = releases/mtls
#   --instance-name   = tesseract-proxy
#   --region          = ap-south-1
#   --availability-zone = ap-south-1a
#   --bundle          = nano_3_1
#   --allowed-cidr    = 0.0.0.0/0   (mTLS handles auth; tighten if you want)
#
# Prereqs:
#   - AWS CLI v2 authenticated; default region not strictly required (we pass --region).
#   - openssh-client (`ssh`, `scp`).
#   - `releases/keys/signing.{key,pub}` and `releases/mtls/` already populated
#     by gen-signing-key.sh + gen-mtls.sh.

set -euo pipefail

TARBALL=""
MTLS_DIR=""
CLIENT_SERIAL=""
INSTANCE_NAME="tesseract-proxy"
REGION="ap-south-1"
AZ="ap-south-1a"
BUNDLE_ID="nano_3_1"
KEY_PAIR=""
SSH_KEY=""
ALLOWED_CIDR="0.0.0.0/0"

while [ $# -gt 0 ]; do
    case "$1" in
        --tarball)           TARBALL="$2"; shift 2 ;;
        --mtls-dir)          MTLS_DIR="$2"; shift 2 ;;
        --client-serial)     CLIENT_SERIAL="$2"; shift 2 ;;
        --instance-name)     INSTANCE_NAME="$2"; shift 2 ;;
        --region)            REGION="$2"; shift 2 ;;
        --availability-zone) AZ="$2"; shift 2 ;;
        --bundle)            BUNDLE_ID="$2"; shift 2 ;;
        --key-pair)          KEY_PAIR="$2"; shift 2 ;;
        --ssh-key)           SSH_KEY="$2"; shift 2 ;;
        --allowed-cidr)      ALLOWED_CIDR="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
done

command -v aws >/dev/null 2>&1 || { echo "aws CLI required" >&2; exit 1; }
command -v ssh >/dev/null 2>&1 || { echo "ssh required" >&2; exit 1; }
command -v scp >/dev/null 2>&1 || { echo "scp required" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Defaults that point at the layout the other R-scripts produce.
[ -n "$MTLS_DIR" ] || MTLS_DIR="$REPO_ROOT/releases/mtls"
if [ -z "$TARBALL" ]; then
    TARBALL=$(ls -t "$REPO_ROOT/releases/"tesseract-proxy-*.tar.gz 2>/dev/null | head -1 || true)
fi

[ -n "$TARBALL" ]       || { echo "--tarball not given and no releases/tesseract-proxy-*.tar.gz found" >&2; exit 1; }
[ -f "$TARBALL" ]       || { echo "tarball not found: $TARBALL" >&2; exit 1; }
[ -d "$MTLS_DIR" ]      || { echo "mtls dir not found: $MTLS_DIR (run gen-mtls.sh)" >&2; exit 1; }
[ -n "$CLIENT_SERIAL" ] || { echo "--client-serial is required (the integer gen-mtls.sh printed)" >&2; exit 1; }

for f in server.pem server.key ca.pem; do
    [ -f "$MTLS_DIR/$f" ] || { echo "missing $MTLS_DIR/$f" >&2; exit 1; }
done

aws() { command aws --region "$REGION" "$@"; }

# --- 1. Create Lightsail instance (idempotent) -----------------------------
if aws lightsail get-instance --instance-name "$INSTANCE_NAME" >/dev/null 2>&1; then
    echo "==> instance '$INSTANCE_NAME' already exists; skipping create"
else
    echo "==> creating Lightsail instance '$INSTANCE_NAME' in $AZ ($BUNDLE_ID)"
    CREATE_ARGS=(
        lightsail create-instances
        --instance-names "$INSTANCE_NAME"
        --availability-zone "$AZ"
        --blueprint-id amazon_linux_2023
        --bundle-id "$BUNDLE_ID"
    )
    [ -n "$KEY_PAIR" ] && CREATE_ARGS+=(--key-pair-name "$KEY_PAIR")
    aws "${CREATE_ARGS[@]}" >/dev/null
fi

echo "==> waiting for instance to reach 'running'"
for i in $(seq 1 60); do
    STATE=$(aws lightsail get-instance --instance-name "$INSTANCE_NAME" \
        --query 'instance.state.name' --output text 2>/dev/null || echo "pending")
    if [ "$STATE" = "running" ]; then break; fi
    sleep 5
done
[ "$STATE" = "running" ] || { echo "instance not running after 5 min (state=$STATE)" >&2; exit 1; }

# --- 2. Static IP (idempotent) ---------------------------------------------
STATIC_IP_NAME="${INSTANCE_NAME}-ip"
if aws lightsail get-static-ip --static-ip-name "$STATIC_IP_NAME" >/dev/null 2>&1; then
    echo "==> static IP '$STATIC_IP_NAME' already allocated"
else
    echo "==> allocating static IP '$STATIC_IP_NAME'"
    aws lightsail allocate-static-ip --static-ip-name "$STATIC_IP_NAME" >/dev/null
fi
ATTACHED_TO=$(aws lightsail get-static-ip --static-ip-name "$STATIC_IP_NAME" \
    --query 'staticIp.attachedTo' --output text 2>/dev/null || echo "None")
if [ "$ATTACHED_TO" != "$INSTANCE_NAME" ]; then
    echo "==> attaching static IP → $INSTANCE_NAME"
    aws lightsail attach-static-ip \
        --static-ip-name "$STATIC_IP_NAME" \
        --instance-name "$INSTANCE_NAME" >/dev/null
fi
IP=$(aws lightsail get-static-ip --static-ip-name "$STATIC_IP_NAME" \
    --query 'staticIp.ipAddress' --output text)
[ -n "$IP" ] && [ "$IP" != "None" ] || { echo "could not read static IP" >&2; exit 1; }
echo "==> static IP = $IP"

# --- 3. Open ports 22 + 443 (idempotent: open-instance-public-ports overlays) -
echo "==> opening inbound 22 + 443 (source $ALLOWED_CIDR)"
aws lightsail put-instance-public-ports \
    --instance-name "$INSTANCE_NAME" \
    --port-infos \
        "fromPort=22,toPort=22,protocol=tcp,cidrs=$ALLOWED_CIDR" \
        "fromPort=443,toPort=443,protocol=tcp,cidrs=$ALLOWED_CIDR" >/dev/null

# --- 4. Wait for SSH -------------------------------------------------------
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5)
[ -n "$SSH_KEY" ] && SSH_OPTS+=(-i "$SSH_KEY")

echo "==> waiting for SSH on $IP"
for i in $(seq 1 60); do
    if ssh "${SSH_OPTS[@]}" -o BatchMode=yes ec2-user@"$IP" true 2>/dev/null; then
        break
    fi
    sleep 5
done
ssh "${SSH_OPTS[@]}" -o BatchMode=yes ec2-user@"$IP" true \
    || { echo "SSH never came up. If you passed --key-pair, also pass --ssh-key with the matching local key." >&2; exit 1; }

# --- 5. SCP the tarball + mTLS server material -----------------------------
echo "==> uploading tarball + mTLS material"
scp "${SSH_OPTS[@]}" "$TARBALL" \
    "$MTLS_DIR/server.pem" "$MTLS_DIR/server.key" "$MTLS_DIR/ca.pem" \
    ec2-user@"$IP":~/

TARBALL_BASENAME=$(basename "$TARBALL")
TARBALL_STEM="${TARBALL_BASENAME%.tar.gz}"

# --- 6. Run install.sh + drop mTLS material into /etc/ ---------------------
echo "==> running install.sh + placing mTLS material"
ssh "${SSH_OPTS[@]}" ec2-user@"$IP" bash <<REMOTE
set -euo pipefail
tar xzf "$TARBALL_BASENAME"
sudo "./$TARBALL_STEM/install.sh"

sudo install -d -o root -g tesseract-proxy -m 0750 /etc/tesseract-proxy/certs
sudo install -o root -g tesseract-proxy -m 0640 server.pem    /etc/tesseract-proxy/certs/
sudo install -o root -g tesseract-proxy -m 0640 server.key    /etc/tesseract-proxy/certs/
sudo install -o root -g tesseract-proxy -m 0640 ca.pem        /etc/tesseract-proxy/certs/client-ca.pem
rm -f server.pem server.key ca.pem "$TARBALL_BASENAME"
REMOTE

# --- 7. Render proxy.conf.yaml with the client serial ----------------------
echo "==> rendering proxy.conf.yaml (client serial $CLIENT_SERIAL)"
TMPCONF=$(mktemp)
trap 'rm -f "$TMPCONF"' EXIT
sed -e "s|\\\"<replace-me>\\\"|\\\"$CLIENT_SERIAL\\\"|g" \
    "$REPO_ROOT/src/release/proxy.conf.yaml.template" > "$TMPCONF" \
    || cp "$REPO_ROOT/src/release/proxy.conf.yaml.template" "$TMPCONF"

scp "${SSH_OPTS[@]}" "$TMPCONF" ec2-user@"$IP":~/proxy.conf.yaml
ssh "${SSH_OPTS[@]}" ec2-user@"$IP" bash <<REMOTE
set -euo pipefail
sudo install -o root -g tesseract-proxy -m 0640 \
    proxy.conf.yaml /etc/tesseract-proxy/proxy.conf.yaml
rm -f proxy.conf.yaml

# Replace allowed-serial placeholders if the template uses tokens like
# {{CLIENT_SERIAL}} (the template format may evolve; sed is no-op if absent).
sudo sed -i -e "s/{{CLIENT_SERIAL}}/$CLIENT_SERIAL/g" \
    /etc/tesseract-proxy/proxy.conf.yaml || true
REMOTE

# --- 8. Enable + start ------------------------------------------------------
echo "==> enabling and starting tesseract-proxy"
ssh "${SSH_OPTS[@]}" ec2-user@"$IP" \
    "sudo systemctl daemon-reload && sudo systemctl enable --now tesseract-proxy"

# --- 9. Status ---------------------------------------------------------------
cat <<DONE

==> deploy complete.

  Instance:  $INSTANCE_NAME ($BUNDLE_ID, $AZ)
  Static IP: $IP        ← whitelist this with each broker
  Tarball:   $TARBALL_BASENAME
  Client allowlist serial: $CLIENT_SERIAL

Watch the proxy come up:
  ssh${SSH_KEY:+ -i $SSH_KEY} ec2-user@$IP sudo journalctl -u tesseract-proxy -f

Audit log (per-request, JSON):
  ssh${SSH_KEY:+ -i $SSH_KEY} ec2-user@$IP sudo tail -f /var/log/tesseract-proxy/audit.log

Push a new tarball later:
  ./update-lightsail.sh --tarball <new.tar.gz> --lightsail-ip $IP${SSH_KEY:+ --ssh-key $SSH_KEY}

Push a new bundle without rebuilding the binary:
  ./reload-bundle.sh --bundle <bundle.yaml> --sig <bundle.yaml.sig> --lightsail-ip $IP${SSH_KEY:+ --ssh-key $SSH_KEY}

DONE
