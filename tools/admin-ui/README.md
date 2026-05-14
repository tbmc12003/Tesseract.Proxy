# admin-ui

Local desktop UI for editing Tesseract broker profiles
(`src/tesseract-proxy-config/brokers/*.yaml`).

## Security model

**No authentication.** The HTTP listener binds `127.0.0.1` only and
hard-fails at startup if the loopback bind is unavailable. There is no
`--listen` flag and no way to expose the UI on any other interface.
Anyone who can reach `127.0.0.1` on this machine can already read and
write the YAML files directly — the UI does not widen that boundary.

## Build

```
cd web
npm install
npm run build      # produces web/dist/bundle.js

cd ..
go build -o admin-ui .
```

The Go binary uses `embed.FS` over `web/dist/`, so the SPA must be built
**before** the Go binary if you want the new frontend baked in.

## Run

```
./admin-ui                       # auto-detects tesseract-proxy-config/
./admin-ui --config-dir ../tesseract-proxy-config
./admin-ui --port 47821 --no-browser
```

Default port: `47821`. Browser opens automatically unless `--no-browser`.

## API (R6.2)

| Method | Path                  | Body              | Notes |
|--------|-----------------------|-------------------|-------|
| GET    | `/api/brokers`        | —                 | List (id, display_name, enabled) |
| GET    | `/api/brokers/{name}` | —                 | Full profile |
| POST   | `/api/brokers`        | broker JSON       | id taken from body; 409 if exists |
| PUT    | `/api/brokers/{name}` | broker JSON       | body.id must equal `{name}` |
| DELETE | `/api/brokers/{name}` | —                 | 204 on success |
| POST   | `/api/publish`        | `{"confirm":"DEPLOY"}` | Streams build+deploy log (chunked text). 412 on wrong phrase, 424 if deploy config missing, 409 if another publish is in flight. |

Every write validates against `schemas/bundle.schema.json`. Bad input
returns `400` with the validator error in `{"error": "..."}`.

## Publish (R6.3)

Publish runs `build-bundle` (Go cmd in `tesseract-proxy/cmd/build-bundle`)
then `release/scripts/reload-bundle.sh`. The `confirm` body field must be
the literal string `DEPLOY` — server-side gate so a bookmark or curl
typo can't push to production.

Deploy parameters live in `tesseract-proxy-config/deploy.local.yaml`
(gitignored via `*.local.yaml`):

```yaml
lightsail_ip: 1.2.3.4
ssh_key:    C:/Users/Sujoy/.ssh/lightsail.pem
signer_key: C:/Dev-wksp/sources/vs2022/equinomics/releases/keys/signing.key
# optional — sensible defaults derived from the workspace layout:
# pubkey:        .../releases/keys/signing.pub
# bundle_out:    .../releases/staging/bundle.yaml
# sig_out:       .../releases/staging/bundle.yaml.sig
# proxy_repo:    .../src/tesseract-proxy
# reload_script: .../src/release/scripts/reload-bundle.sh
```

Without that file, `Publish` returns `424 Failed Dependency` with the
list of missing fields. The binary still starts.

## Phase status

- R6.1 ✅ Go cmd skeleton + embed.FS + browser launch
- R6.2 ✅ Broker CRUD endpoints with schema validation
- R6.3 ✅ Publish flow (build + deploy with `DEPLOY` confirmation gate)
- R6.6 ✅ Loopback-only enforcement (hard-fail)
- R6.4 ⏳ URL editor table UX
- R6.5 ⏳ Diff preview before publish
