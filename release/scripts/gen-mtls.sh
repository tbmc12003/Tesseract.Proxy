#!/usr/bin/env bash
#
# gen-mtls.sh — generate the ECDSA P-256 mTLS chain for the proxy + Tesseract.
#
# Mints (all ECDSA P-256, certs signed with ECDSA-with-SHA256):
#   ca.pem / ca.key             — your CA. ca.key is the trust root. KEEP IT SECRET.
#   server.pem / server.key     — proxy's TLS server cert, SAN = Lightsail IP.
#                                 → deploy to /etc/tesseract-proxy/certs/ on Lightsail.
#   client.pem / client.key     — Tesseract desktop's client cert.
#   client.p12                  — PKCS#12 bundle of client cert + key, AES-256.
#                                 → loaded by Tesseract's PfxFileCertificateProvider.
#   client-ca.pem               — copy of ca.pem under the name proxy.conf.yaml expects.
#
# After running, the CLIENT SERIAL is printed — paste it into proxy.conf.yaml
# under mtls.allowed_order_serials AND allowed_admin_serials.
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
#                             Empty string disables encryption (not recommended).
#   --reuse-ca                Keep ca.{pem,key}; mint fresh server + client.
#   --reuse-server            Keep ca + server; mint fresh client only.
#                             (Primary flow for admin-UI client re-issue.)
#   --force                   Overwrite output without prompting.
#
# Why ECDSA P-256:
#   .NET / Schannel rejects Ed25519 client certs at parse time
#   (X509Certificate2.CreateFromPemFile fails on OID 1.3.101.112).
#   ECDSA P-256 is first-class in .NET, Go, and OpenSSL — one algorithm
#   across the whole stack.

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
            sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'
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

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

# Sanity for reuse modes.
if [ "$REUSE_CA" -eq 1 ] || [ "$REUSE_SERVER" -eq 1 ]; then
    [ -f ca.key ] && [ -f ca.pem ] || {
        echo "reuse mode requested but ca.{key,pem} not present in $OUT_DIR" >&2; exit 1
    }
fi
if [ "$REUSE_SERVER" -eq 1 ]; then
    [ -f server.pem ] && [ -f server.key ] || {
        echo "--reuse-server requested but server.{pem,key} not present in $OUT_DIR" >&2; exit 1
    }
fi

# Refuse to clobber an existing client cert unless --force or a reuse mode is in play.
if [ -f client.pem ] && [ "$FORCE" -ne 1 ] && [ "$REUSE_SERVER" -eq 0 ] && [ "$REUSE_CA" -eq 0 ]; then
    echo "client.pem already exists in $OUT_DIR — pass --force or a --reuse-* flag" >&2
    exit 1
fi

# Prompt for the PKCS#12 password if not provided. Empty password is allowed
# but warns — Tesseract's PfxFileCertificateProvider takes the password via
# config, so encrypting is virtually free.
if [ "$P12_PASS_SET" -eq 0 ]; then
    printf "client.p12 password (empty to skip encryption): "
    read -r -s P12_PASS
    printf "\n"
fi

# --- CA ---------------------------------------------------------------------
if [ "$REUSE_CA" -eq 0 ] && [ "$REUSE_SERVER" -eq 0 ]; then
    echo "==> generating ECDSA P-256 CA"
    openssl genpkey \
        -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve \
        -out ca.key
    chmod 0600 ca.key
    openssl req -new -x509 -key ca.key -days "$DAYS" -sha256 \
        -subj "/CN=$CA_CN" -out ca.pem
fi

# --- Server -----------------------------------------------------------------
if [ "$REUSE_SERVER" -eq 0 ]; then
    echo "==> generating ECDSA P-256 server cert (SAN = $LIGHTSAIL_IP)"
    openssl genpkey \
        -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve \
        -out server.key
    chmod 0600 server.key
    cat > server.ext <<EOF
subjectAltName = IP:$LIGHTSAIL_IP
extendedKeyUsage = serverAuth
EOF
    openssl req -new -key server.key -subj "/CN=$SERVER_CN" -out server.csr
    openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
        -days "$DAYS" -sha256 -extfile server.ext -out server.pem
    rm server.csr server.ext

    # The proxy's config expects the client CA under this name.
    cp ca.pem client-ca.pem
fi

# --- Client -----------------------------------------------------------------
echo "==> generating ECDSA P-256 client cert (serial=$CLIENT_SERIAL)"
openssl genpkey \
    -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve \
    -out client.key
chmod 0600 client.key
cat > client.ext <<EOF
extendedKeyUsage = clientAuth
EOF
openssl req -new -key client.key -subj "/CN=$CLIENT_CN" -out client.csr
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -set_serial "$CLIENT_SERIAL" \
    -days "$DAYS" -sha256 -extfile client.ext -out client.pem
rm client.csr client.ext

# --- client.p12 for .NET ----------------------------------------------------
# AES-256 for both cert and key bags; SHA-256 MAC. Modern enough for .NET 8+
# X509Certificate2.CreateFromPkcs12 and avoids the legacy RC2/SHA1 path.
echo "==> bundling client.p12 (PKCS#12, AES-256)"
rm -f client.p12
openssl pkcs12 -export \
    -inkey client.key -in client.pem -certfile ca.pem \
    -name "tesseract-order-client" \
    -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256 \
    -passout "pass:$P12_PASS" \
    -out client.p12
chmod 0600 client.p12

# --- Verify -----------------------------------------------------------------
echo "==> verifying chain"
openssl verify -CAfile ca.pem server.pem >/dev/null
openssl verify -CAfile ca.pem client.pem >/dev/null

ACTUAL_SERIAL=$(openssl x509 -in client.pem -noout -serial | sed 's/serial=//' | tr 'A-F' 'a-f')
ACTUAL_DECIMAL=$(printf '%d\n' "0x$ACTUAL_SERIAL")

cat <<NEXT

==> done. Files in $(pwd):

  CA (KEEP ca.key SECRET):
    ca.pem             public CA cert
    ca.key             CA private key (0600)
    client-ca.pem      copy of ca.pem under the name proxy.conf.yaml expects

  Server (deploy to Lightsail):
    server.pem
    server.key         (0600)

  Client (point Tesseract's brokerProfiles.json at one of these):
    client.pem / client.key
    client.p12         (0600, AES-256)

==> CLIENT SERIAL: $ACTUAL_DECIMAL

   Add to /etc/tesseract-proxy/proxy.conf.yaml on Lightsail:

      mtls:
        allowed_order_serials: ["$ACTUAL_DECIMAL"]
        allowed_admin_serials: ["$ACTUAL_DECIMAL"]

==> next steps:

  # First-time deploy (or after --reuse-ca/--reuse-server mints fresh server):
  scp $(pwd)/server.pem $(pwd)/server.key $(pwd)/client-ca.pem ec2-user@${LIGHTSAIL_IP:-<ip>}:~
  ssh ec2-user@${LIGHTSAIL_IP:-<ip>} \\
      "sudo install -o root -g tesseract-proxy -m 0640 server.pem server.key client-ca.pem /etc/tesseract-proxy/certs/ && rm server.{pem,key} client-ca.pem"

  # Client-only re-issue (--reuse-server): no server redeploy, just allowlist update + reload.
  # Edit proxy.conf.yaml with the new serial above, then:
  ssh ec2-user@${LIGHTSAIL_IP:-<ip>} "sudo systemctl reload tesseract-proxy"

NEXT
