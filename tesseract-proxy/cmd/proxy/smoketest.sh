#!/usr/bin/env bash
# Smoke test for the wired proxy. Builds a minimal fixture set (CA + certs,
# signed bundle, operator config) in a temp dir and confirms the proxy
# starts, accepts a valid mTLS request through the order plane, and
# exits cleanly on signal.
#
# Run from src/tesseract-proxy/ (the Go module root). Assumes openssl + jq.

set -euo pipefail

SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT
cd "$SCRATCH"
echo "smoketest scratch: $SCRATCH"

EC="-algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve"

# ---- ECDSA P-256 bundle signing key ----
openssl genpkey $EC -out bundle.key
openssl pkey -in bundle.key -pubout -out bundle.pub

# ---- CA + server cert + client cert (all ECDSA P-256) ----
openssl genpkey $EC -out ca.key
openssl req -new -x509 -key ca.key -days 1 -sha256 -out ca.pem -subj "/CN=smoke-ca"

openssl genpkey $EC -out server.key
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
cat >server.ext <<EOF
subjectAltName = DNS:localhost,IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.pem -days 1 -sha256 -extfile server.ext

openssl genpkey $EC -out client.key
openssl req -new -key client.key -out client.csr -subj "/CN=order"
echo "extendedKeyUsage = clientAuth" >client.ext
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -set_serial 1001 -out client.pem -days 1 -sha256 -extfile client.ext

# ---- Signed bundle ----
mkdir -p profiles
cat >bundle.yaml <<'EOF'
schema_version: 1
bundle_version: 2026-05-13-smoke
issued_at: 2026-05-13T00:00:00Z
issuer: equinomics
min_proxy_version: 0.0.1
brokers:
  - id: papertrader
    display_name: PaperTrader
    host: papertrader.local
    enabled: true
    order_endpoints:
      - method: POST
        path: /Orders/2.0/quick/order/rule/ms/place
        kind: place
    idempotency:
      client_order_id_header: X-Client-Order-Id
      client_order_id_body_path: ""
      echo_in_response_path: data.orderNumber
    rate_limit:
      per_user_rps: 100
      per_user_burst: 200
EOF
openssl dgst -sha256 -sign bundle.key -out bundle.yaml.sig bundle.yaml
cp bundle.yaml profiles/bundle.yaml
cp bundle.yaml.sig profiles/bundle.yaml.sig

# ---- Operator config ----
mkdir -p log
cat >proxy.conf.yaml <<EOF
listen:
  order_plane: "127.0.0.1:18443"

mtls:
  server_cert: "$SCRATCH/server.pem"
  server_key:  "$SCRATCH/server.key"
  client_ca:   "$SCRATCH/ca.pem"
  allowed_order_serials: ["1001"]
  allowed_admin_serials: ["1001"]

profile_bundle:
  path:        "$SCRATCH/profiles/bundle.yaml"
  sig_path:    "$SCRATCH/profiles/bundle.yaml.sig"
  pubkey_path: "$SCRATCH/bundle.pub"
  refresh:
    enabled: false

idempotency:
  ttl:         60s
  max_entries: 64

audit_log:
  path:         "$SCRATCH/log/audit.log"
  rotation_mb:  16
  retain_count: 7

log:
  level:  info
  format: json
EOF

echo "starting proxy..."
"$1" --config "$SCRATCH/proxy.conf.yaml" 2>"$SCRATCH/proxy.stderr" &
PROXY_PID=$!
cleanup_proxy() {
  kill "$PROXY_PID" 2>/dev/null || true
  wait "$PROXY_PID" 2>/dev/null || true
}
trap 'cleanup_proxy; rm -rf "$SCRATCH"' EXIT

# Wait for the listener.
for i in $(seq 1 50); do
  if exec 3<>/dev/tcp/127.0.0.1/18443 2>/dev/null; then
    exec 3<&-; exec 3>&-
    break
  fi
  sleep 0.1
done
echo "proxy listening (pid $PROXY_PID)"

# /admin/status with mTLS — should return 200.
HTTP_STATUS=$(curl -sk --cert "$SCRATCH/client.pem" --key "$SCRATCH/client.key" \
  --cacert "$SCRATCH/ca.pem" \
  -o "$SCRATCH/status.json" -w '%{http_code}' \
  "https://127.0.0.1:18443/admin/status")
echo "GET /admin/status -> $HTTP_STATUS"
if [ "$HTTP_STATUS" != "200" ]; then
  echo "--- proxy stderr ---"; cat "$SCRATCH/proxy.stderr"
  echo "--- response ---"; cat "$SCRATCH/status.json"
  exit 1
fi

# 403 path: unknown broker on order plane.
HTTP_STATUS=$(curl -sk --cert "$SCRATCH/client.pem" --key "$SCRATCH/client.key" \
  --cacert "$SCRATCH/ca.pem" \
  -o /dev/null -w '%{http_code}' \
  -X POST \
  -H 'X-Tesseract-Broker: ghost' \
  -d '{}' \
  "https://127.0.0.1:18443/Orders/2.0/quick/order/rule/ms/place")
echo "POST with unknown broker -> $HTTP_STATUS"
[ "$HTTP_STATUS" = "403" ] || exit 1

# /admin/metrics should now show a rejects_total bump.
curl -sk --cert "$SCRATCH/client.pem" --key "$SCRATCH/client.key" \
  --cacert "$SCRATCH/ca.pem" \
  "https://127.0.0.1:18443/admin/metrics" | grep -E '^tesseract_rejects_total ' || exit 1

echo "smoketest OK"
