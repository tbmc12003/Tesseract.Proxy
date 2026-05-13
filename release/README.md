# tesseract-proxy — deploy walkthrough

Single-user BYOC deployment on AWS Lightsail. ~15 minutes start to first
forwarded order, assuming you already have an AWS account.

## What you need before starting

- AWS account (yours — this is BYOC; nothing lives in Equinomics infra).
- Domain or IP your brokers will whitelist (this Lightsail instance's
  static IP — you'll get it after step 2).
- Tesseract desktop installed locally, holding the CA private key it'll
  use to mint client certs.
- This tarball: `tesseract-proxy-<version>-linux-arm64.tar.gz`.

## What the proxy does

Forwards order REST requests from Tesseract → broker over mTLS. **That's
it.** Market data, order-status websockets, quotes, holdings — all flow
direct from broker to desktop, bypassing this box. The only reason this
exists is to give SEBI's static-IP rule a whitelist target.

## 1. Provision Lightsail

Either run the bundled CloudFormation template (`deploy/cfn.yaml`) or
do it by hand:

```
aws lightsail create-instances \
    --instance-names tesseract-proxy \
    --availability-zone ap-south-1a \
    --blueprint-id amazon_linux_2023 \
    --bundle-id nano_3_0 \
    --user-data file://user-data.sh

aws lightsail allocate-static-ip --static-ip-name tesseract-proxy-ip
aws lightsail attach-static-ip --static-ip-name tesseract-proxy-ip \
    --instance-name tesseract-proxy
```

Note the static IP — this is what you whitelist with brokers.

## 2. Install the proxy

`scp` the tarball to the instance, untar, run install.sh as root:

```
scp tesseract-proxy-v0.1.0-linux-arm64.tar.gz ec2-user@<ip>:~/
ssh ec2-user@<ip>
tar xzf tesseract-proxy-v0.1.0-linux-arm64.tar.gz
cd tesseract-proxy-v0.1.0-linux-arm64
sudo ./install.sh
```

install.sh verifies the bundled Ed25519 signatures on the binary and
bundle against the included pubkey before touching anything else. If
verification fails the install aborts and nothing is written.

Verification confirms what the tarball contains — the same chain runs
again at runtime when the proxy boots and re-verifies the bundle.

## 3. Generate mTLS material from Tesseract

On the desktop, in Tesseract:

1. Run the cert-generation wizard (Phase 5; once available). It mints:
   - your CA (kept in DPAPI on the desktop)
   - server cert + key signed by the CA (uploaded to Lightsail)
   - one or two client certs signed by the CA (kept in DPAPI, presented
     on every order request)
2. Note the serial numbers of the client certs — these go into the
   proxy's `allowed_order_serials` / `allowed_admin_serials` lists.

Upload the server material:

```
scp server.pem server.key client-ca.pem ec2-user@<ip>:~/
ssh ec2-user@<ip>
sudo install -o root -g tesseract-proxy -m 0640 server.pem /etc/tesseract-proxy/certs/
sudo install -o root -g tesseract-proxy -m 0640 server.key /etc/tesseract-proxy/certs/
sudo install -o root -g tesseract-proxy -m 0640 client-ca.pem /etc/tesseract-proxy/certs/
```

## 4. Edit `/etc/tesseract-proxy/proxy.conf.yaml`

The installer drops a starter file. The only required edits are the
allowed-serial lists:

```
mtls:
  allowed_order_serials: ["<your-client-cert-serial>"]
  allowed_admin_serials: ["<your-client-cert-serial>"]
```

Everything else is sane-defaulted for a single Lightsail box. See the
inline comments for optional knobs (`egress:`, `binary:`).

## 5. Start the service

```
sudo systemctl enable --now tesseract-proxy
sudo systemctl status tesseract-proxy
sudo journalctl -u tesseract-proxy -f
```

You should see:

```
{"level":"INFO","msg":"initial bundle loaded","bundle_version":"...","brokers":3}
{"level":"INFO","msg":"listening","addr":"0.0.0.0:443"}
```

## 6. Whitelist the static IP with your broker

Per-broker: log into the broker's developer console, find "API IP
allowlist" (Kotak Neo: "Trade API → Whitelist IPs"; Fyers: "App
settings → IP whitelist"), paste your Lightsail static IP.

## 7. Smoke-test from the desktop

In Tesseract, place a small test order. Watch the audit log:

```
sudo tail -f /var/log/tesseract-proxy/audit.log
```

Each forwarded order produces one JSON line with the outcome and the
broker's response status. If you see `"outcome":"forward"` and a 2xx
status, you're live.

## Failure modes — quick triage

| Symptom | Probable cause |
|---|---|
| `systemctl status` shows "initial bundle: profile: signature verification failed" | Bundle file on disk doesn't match its `.sig`. Most likely cause: the bundle was edited after signing. Re-deploy from the tarball. |
| Tesseract gets `connection refused` | Lightsail firewall doesn't allow inbound 443. `aws lightsail open-instance-public-ports`. |
| Tesseract gets `bad certificate` | Client cert serial isn't in `allowed_order_serials`. Add it and `systemctl reload tesseract-proxy`. |
| Order returns 403 from the proxy | Broker / method / path doesn't match the signed bundle's allowlist. Check `journalctl -u tesseract-proxy` for the structured reject line. |
| Order returns 502 from the proxy | Broker upstream failure. Check `audit.log` `reason` field. |
| Broker returns 401 / 403 | Your broker access token expired or your IP isn't whitelisted there yet. |

## Operating

- **Rotate logs:** `logrotate(8)` with a config in `/etc/logrotate.d/tesseract-proxy` calls
  `systemctl reload tesseract-proxy` after rotation; the proxy reopens
  the audit log on SIGHUP.
- **Reload bundle without restart:** `systemctl reload tesseract-proxy`.
- **Update the binary in place:** `POST /admin/binary/upload` over mTLS
  (admin cert) with the new binary + sig as multipart form parts. The
  proxy stages, verifies, swaps; you then restart.
- **Rollback:** `tesseract-proxy --rollback-bundle` or
  `tesseract-proxy --rollback-binary` swaps `.previous` into the active
  slot then exits. Re-run systemctl start.

## What's NOT in this tarball

- The Tesseract desktop app (separate distribution).
- The mTLS CA + client cert generation wizard (Phase 5, Tesseract-side).
- The `cfg.tesseract.in` bundle-update CDN (P0.9 / P4.6). For now the
  bundle ships embedded in this tarball; you re-deploy the tarball to
  update the bundle.

## Verifying tarball signatures yourself

```
sha256sum tesseract-proxy-v0.1.0-linux-arm64.tar.gz
# compare against the .sha256 file accompanying the release

# After untar, before running install.sh:
openssl pkeyutl -verify \
    -pubin -inkey etc/pubkey/equinomics-signing.pub \
    -rawin -in bin/proxy -sigfile bin/proxy.sig
# should print: Signature Verified Successfully
```
