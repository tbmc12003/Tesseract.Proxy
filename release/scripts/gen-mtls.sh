#!/usr/bin/env bash
#
# gen-mtls.sh — generate the ECDSA P-256 mTLS chain for the proxy + Tesseract.
#
# Layout (all under $OUT_DIR, default releases/mtls/):
#
#   root-ca/
#     ca.pem                   public CA cert
#     ca.key                   CA private key (0600) — KEEP SECRET
#
#   proxy/
#     server.pem               server cert, SAN = Lightsail IP
#     server.key               (0600) — deploy to Lightsail
#     trust-bundle.pem         copy of root-ca/ca.pem — uploaded next to the
#                              server so the proxy can verify client certs
#
#   tesseract/
#     client.pem / client.key  client cert + key (0600)
#     client.p12               PKCS#12 bundle for .NET's PfxFileCertificateProvider
#
# All certs use ECDSA P-256 keys, signed with ECDSA-with-SHA256. There is no
# Ed25519 code path in this script — Ed25519 is rejected by .NET/Schannel.
#
# Usage:
#   ./gen-mtls.sh --lightsail-ip 1.2.3.4 [options]
#
# Options:
#   --lightsail-ip <ip>       Required for fresh CA/server. Becomes the server cert SAN.
#   --out <dir>               Output dir. Default: releases/mtls
#   --client-serial <int>     Decimal serial baked into client cert. Default: 1001
#   --days <n>                Cert validity. Default: 365
#   --p12-pass <password>     Password for client.p12. If omitted, prompts.
#                             Empty string disables encryption.
#   --reuse-ca                Keep root-ca/; mint fresh proxy + tesseract material.
#   --reuse-server            Keep root-ca/ + proxy/; mint fresh tesseract/ only.
#                             (Primary flow for admin-UI client re-issue.)
#   --force                   Overwrite output without prompting.

set -euo pipefail

# On Git-Bash / MSYS / Cygwin, "/CN=foo" gets path-converted to "C:/.../CN=foo".
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

LIGHTSAIL_IP=""
OUT_DIR=""
CLIENT_SERIAL=1001
DAYS=365
CA_CN="tesseract-user-ca"
SERVER_CN="tesseract-proxy"
CLIENT_CN="tesseract-order-client"
REUSE_CA=0
REUSE_SERVER=0
P12_PASS=""
P12_PASS_SET=0
FORCE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --lightsail-ip)   LIGHTSAIL_IP="$2"; shift 2 ;;
        --out)            OUT_DIR="$2"; shift 2 ;;
        --client-serial)  CLIENT_SERIAL="$2"; shift 2 ;;
        --days)           DAYS="$2"; shift 2 ;;
        --p12-pass)       P12_PASS="$2"; P12_PASS_SET=1; shift 2 ;;
        --reuse-ca)       REUSE_CA=1; shift ;;
        --reuse-server)   REUSE_SERVER=1; shift ;;
        --force)          FORCE=1; shift ;;
        -h|--help)
            sed -n '2,38p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
done

if [ "$REUSE_CA" -eq 1 ] && [ "$REUSE_SERVER" -eq 1 ]; then
    echo "--reuse-ca and --reuse-server are mutually exclusive" >&2; exit 1
fi

command -v openssl >/dev/null 2>&1 || { echo "openssl is required" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
[ -n "$OUT_DIR" ] || OUT_DIR="$REPO_ROOT/releases/mtls"

# --lightsail-ip required only when minting a fresh server cert.
if [ "$REUSE_SERVER" -eq 0 ] && [ -z "$LIGHTSAIL_IP" ]; then
    echo "--lightsail-ip is required (the static IP Lightsail returns)" >&2; exit 1
fi

mkdir -p "$OUT_DIR/root-ca" "$OUT_DIR/proxy" "$OUT_DIR/tesseract"

# On Git-Bash / MSYS, openssl is a native Windows binary that doesn't speak
# POSIX paths. Convert to mixed format (C:/foo/bar) for openssl args.
if command -v cygpath >/dev/null 2>&1; then
    CA_DIR="$(cygpath -m "$OUT_DIR/root-ca")"
    PROXY_DIR="$(cygpath -m "$OUT_DIR/proxy")"
    CLIENT_DIR="$(cygpath -m "$OUT_DIR/tesseract")"
else
    CA_DIR="$OUT_DIR/root-ca"
    PROXY_DIR="$OUT_DIR/proxy"
    CLIENT_DIR="$OUT_DIR/tesseract"
fi

# Sanity for reuse modes.
if [ "$REUSE_CA" -eq 1 ] || [ "$REUSE_SERVER" -eq 1 ]; then
    [ -f "$CA_DIR/ca.key" ] && [ -f "$CA_DIR/ca.pem" ] || {
        echo "reuse mode requested but $CA_DIR/ca.{key,pem} not present" >&2; exit 1
    }
fi
if [ "$REUSE_SERVER" -eq 1 ]; then
    [ -f "$PROXY_DIR/server.pem" ] && [ -f "$PROXY_DIR/server.key" ] || {
        echo "--reuse-server requested but $PROXY_DIR/server.{pem,key} not present" >&2; exit 1
    }
fi

# Refuse to clobber an existing client cert unless --force or a reuse mode is in play.
if [ -f "$CLIENT_DIR/client.pem" ] && [ "$FORCE" -ne 1 ] && [ "$REUSE_SERVER" -eq 0 ] && [ "$REUSE_CA" -eq 0 ]; then
    echo "$CLIENT_DIR/client.pem already exists — pass --force or a --reuse-* flag" >&2
    exit 1
fi

# Prompt for the PKCS#12 password if not provided.
if [ "$P12_PASS_SET" -eq 0 ]; then
    printf "client.p12 password (empty to skip encryption): "
    read -r -s P12_PASS
    printf "\n"
fi

# --- CA ---------------------------------------------------------------------
if [ "$REUSE_CA" -eq 0 ] && [ "$REUSE_SERVER" -eq 0 ]; then
    echo "==> generating ECDSA P-256 CA → $CA_DIR/"
    openssl genpkey \
        -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve \
        -out "$CA_DIR/ca.key"
    chmod 0600 "$CA_DIR/ca.key"
    openssl req -new -x509 -key "$CA_DIR/ca.key" -days "$DAYS" -sha256 \
        -subj "/CN=$CA_CN" -out "$CA_DIR/ca.pem"
fi

# --- Server (proxy) ---------------------------------------------------------
if [ "$REUSE_SERVER" -eq 0 ]; then
    echo "==> generating ECDSA P-256 server cert (SAN = $LIGHTSAIL_IP) → $PROXY_DIR/"
    openssl genpkey \
        -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve \
        -out "$PROXY_DIR/server.key"
    chmod 0600 "$PROXY_DIR/server.key"
    cat > "$PROXY_DIR/server.ext" <<EOF
subjectAltName = IP:$LIGHTSAIL_IP
extendedKeyUsage = serverAuth
EOF
    openssl req -new -key "$PROXY_DIR/server.key" -subj "/CN=$SERVER_CN" -out "$PROXY_DIR/server.csr"
    openssl x509 -req -in "$PROXY_DIR/server.csr" \
        -CA "$CA_DIR/ca.pem" -CAkey "$CA_DIR/ca.key" -CAcreateserial \
        -days "$DAYS" -sha256 -extfile "$PROXY_DIR/server.ext" \
        -out "$PROXY_DIR/server.pem"
    rm "$PROXY_DIR/server.csr" "$PROXY_DIR/server.ext"

    # The proxy needs the CA to validate incoming clients. Ships next to the server.
    cp "$CA_DIR/ca.pem" "$PROXY_DIR/trust-bundle.pem"
fi

# --- Client (tesseract) -----------------------------------------------------
echo "==> generating ECDSA P-256 client cert (serial=$CLIENT_SERIAL) → $CLIENT_DIR/"
openssl genpkey \
    -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve \
    -out "$CLIENT_DIR/client.key"
chmod 0600 "$CLIENT_DIR/client.key"
cat > "$CLIENT_DIR/client.ext" <<EOF
extendedKeyUsage = clientAuth
EOF
openssl req -new -key "$CLIENT_DIR/client.key" -subj "/CN=$CLIENT_CN" -out "$CLIENT_DIR/client.csr"
openssl x509 -req -in "$CLIENT_DIR/client.csr" \
    -CA "$CA_DIR/ca.pem" -CAkey "$CA_DIR/ca.key" -set_serial "$CLIENT_SERIAL" \
    -days "$DAYS" -sha256 -extfile "$CLIENT_DIR/client.ext" \
    -out "$CLIENT_DIR/client.pem"
rm "$CLIENT_DIR/client.csr" "$CLIENT_DIR/client.ext"

# --- client.p12 for .NET ----------------------------------------------------
echo "==> bundling client.p12 (PKCS#12, AES-256) → $CLIENT_DIR/"
rm -f "$CLIENT_DIR/client.p12"
openssl pkcs12 -export \
    -inkey "$CLIENT_DIR/client.key" -in "$CLIENT_DIR/client.pem" -certfile "$CA_DIR/ca.pem" \
    -name "tesseract-order-client" \
    -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256 \
    -passout "pass:$P12_PASS" \
    -out "$CLIENT_DIR/client.p12"
chmod 0600 "$CLIENT_DIR/client.p12"

# --- Verify -----------------------------------------------------------------
echo "==> verifying chain"
openssl verify -CAfile "$CA_DIR/ca.pem" "$PROXY_DIR/server.pem" >/dev/null
openssl verify -CAfile "$CA_DIR/ca.pem" "$CLIENT_DIR/client.pem" >/dev/null

ACTUAL_SERIAL=$(openssl x509 -in "$CLIENT_DIR/client.pem" -noout -serial | sed 's/serial=//' | tr 'A-F' 'a-f')
ACTUAL_DECIMAL=$(printf '%d\n' "0x$ACTUAL_SERIAL")

cat <<NEXT

==> done. Files under $OUT_DIR:

  root-ca/
    ca.pem               public CA cert
    ca.key               CA private key (0600) — KEEP SECRET

  proxy/
    server.pem           server cert (SAN = ${LIGHTSAIL_IP:-<reused>})
    server.key           (0600)
    trust-bundle.pem     CA copy for the proxy to validate clients

  tesseract/
    client.pem
    client.key           (0600)
    client.p12           (0600, AES-256, PBES2/SHA-256)

==> CLIENT SERIAL: $ACTUAL_DECIMAL

   Add to /etc/tesseract-proxy/proxy.conf.yaml on Lightsail:

      mtls:
        allowed_order_serials: ["$ACTUAL_DECIMAL"]
        allowed_admin_serials: ["$ACTUAL_DECIMAL"]

==> next steps:

  # First-time deploy (or after --reuse-ca/--reuse-server mints fresh server):
  scp $PROXY_DIR/server.pem $PROXY_DIR/server.key $PROXY_DIR/trust-bundle.pem \\
      ec2-user@${LIGHTSAIL_IP:-<ip>}:~
  ssh ec2-user@${LIGHTSAIL_IP:-<ip>} \\
      "sudo install -o root -g tesseract-proxy -m 0640 server.pem server.key trust-bundle.pem /etc/tesseract-proxy/certs/ && rm server.{pem,key} trust-bundle.pem"

  # Client-only re-issue (--reuse-server): no server redeploy, just allowlist update + reload.
  ssh ec2-user@${LIGHTSAIL_IP:-<ip>} "sudo systemctl reload tesseract-proxy"

NEXT
