#!/usr/bin/env bash
#
# tesseract-proxy installer
#
# Run as root on the target Lightsail instance (Amazon Linux 2023 arm64).
# Idempotent — re-running upgrades binaries + systemd unit, leaves config
# and certs in place.
#
# What this does:
#   1. Verifies the bundled ECDSA P-256 / SHA-256 signatures on `proxy` and
#      `bundle.yaml` against the included pubkey (`equinomics-signing.pub`).
#   2. Creates the `tesseract-proxy` system user / group (no shell).
#   3. Lays out directories with correct ownership + modes.
#   4. Copies binaries to /opt/tesseract-proxy/.
#   5. Copies systemd unit to /etc/systemd/system/, reloads systemd.
#   6. Writes a *starter* /etc/tesseract-proxy/proxy.conf.yaml IF none
#      exists (operator fills in cert paths + allowed serials).
#   7. Does NOT start the service. Operator does that after configuring
#      certs + allowed serials. `systemctl enable --now tesseract-proxy`.

set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_NAME=tesseract-proxy
GROUP_NAME=tesseract-proxy

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh: must run as root (try sudo)" >&2
    exit 1
fi

echo "==> verifying bundled signatures"
verify_sig() {
    local file="$1" sig="$2"
    if ! command -v openssl >/dev/null 2>&1; then
        echo "openssl required for signature verification" >&2; exit 1
    fi
    if ! openssl dgst -sha256 \
        -verify "$SRC_DIR/etc/pubkey/equinomics-signing.pub" \
        -signature "$sig" "$file" >/dev/null; then
        echo "FATAL: signature verification failed for $file" >&2
        exit 1
    fi
    echo "    ok: $(basename "$file")"
}
verify_sig "$SRC_DIR/bin/proxy"            "$SRC_DIR/bin/proxy.sig"
verify_sig "$SRC_DIR/etc/profiles/bundle.yaml" "$SRC_DIR/etc/profiles/bundle.yaml.sig"

echo "==> ensuring user/group $USER_NAME"
if ! getent group  "$GROUP_NAME" >/dev/null 2>&1; then
    groupadd --system "$GROUP_NAME"
fi
if ! getent passwd "$USER_NAME" >/dev/null 2>&1; then
    useradd --system --gid "$GROUP_NAME" --no-create-home \
        --shell /usr/sbin/nologin --comment "tesseract-proxy daemon" "$USER_NAME"
fi

echo "==> creating directories"
install -d -o root -g root -m 0755 /opt/tesseract-proxy
install -d -o root -g "$GROUP_NAME" -m 0750 /etc/tesseract-proxy
install -d -o root -g "$GROUP_NAME" -m 0750 /etc/tesseract-proxy/certs
install -d -o root -g "$GROUP_NAME" -m 0750 /etc/tesseract-proxy/profiles
install -d -o root -g "$GROUP_NAME" -m 0755 /etc/tesseract-proxy/pubkey
install -d -o "$USER_NAME" -g "$GROUP_NAME" -m 0750 /var/log/tesseract-proxy

echo "==> installing binaries to /opt/tesseract-proxy"
install -o root -g root -m 0755 "$SRC_DIR/bin/proxy" /opt/tesseract-proxy/proxy
if [ -f "$SRC_DIR/bin/tesseract-proxy-egress" ]; then
    install -o root -g root -m 0755 "$SRC_DIR/bin/tesseract-proxy-egress" \
        /opt/tesseract-proxy/tesseract-proxy-egress
fi

echo "==> installing bundle + pubkey"
install -o root -g "$GROUP_NAME" -m 0640 \
    "$SRC_DIR/etc/profiles/bundle.yaml"     /etc/tesseract-proxy/profiles/bundle.yaml
install -o root -g "$GROUP_NAME" -m 0640 \
    "$SRC_DIR/etc/profiles/bundle.yaml.sig" /etc/tesseract-proxy/profiles/bundle.yaml.sig
install -o root -g "$GROUP_NAME" -m 0644 \
    "$SRC_DIR/etc/pubkey/equinomics-signing.pub" \
    /etc/tesseract-proxy/pubkey/equinomics-signing.pub

echo "==> installing systemd unit"
install -o root -g root -m 0644 \
    "$SRC_DIR/systemd/tesseract-proxy.service" /etc/systemd/system/tesseract-proxy.service
systemctl daemon-reload

if [ ! -f /etc/tesseract-proxy/proxy.conf.yaml ]; then
    echo "==> writing starter /etc/tesseract-proxy/proxy.conf.yaml (operator must edit before starting)"
    install -o root -g "$GROUP_NAME" -m 0640 \
        "$SRC_DIR/etc/proxy.conf.yaml.template" /etc/tesseract-proxy/proxy.conf.yaml
fi

cat <<'NEXT'

==> install complete.

NEXT STEPS (operator):

  1. Drop mTLS material into /etc/tesseract-proxy/certs/:
        - server.pem, server.key       (mTLS server cert, signed by your CA)
        - client-ca.pem                (the CA Tesseract uses to mint client certs)

  2. Edit /etc/tesseract-proxy/proxy.conf.yaml — at minimum:
        mtls.allowed_order_serials, mtls.allowed_admin_serials

  3. Start the proxy:
        systemctl enable --now tesseract-proxy
        systemctl status tesseract-proxy
        journalctl -u tesseract-proxy -f

  4. Note your Lightsail static IP and whitelist it with each broker.

NEXT
