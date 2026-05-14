# admin-ui

Local desktop UI for the Tesseract proxy. Two responsibilities:

1. **Broker config CRUD** — edit `src/tesseract-proxy-config/brokers/*.yaml`
   and publish a fresh signed bundle to Lightsail (R6).
2. **Audit log viewer** — live tail + historical scan over the existing
   ECDSA mTLS chain, with filters, export, rotation, and a health
   indicator (R7).

## Security model

**No authentication.** The HTTP listener binds `127.0.0.1` only and
hard-fails at startup if the loopback bind is unavailable. There is no
`--listen` flag and no way to expose the UI on any other interface.
Anyone who can reach `127.0.0.1` on this machine can already read and
write the YAML files directly — the UI does not widen that boundary.

The audit viewer talks to the proxy over mTLS: admin-ui holds the
client cert, the browser only ever sees plain HTTP over loopback.
Rotating `client.p12` via
`gen-mtls.sh --reuse-server --client-serial N` invalidates audit-viewer
access alongside Tesseract's order-placement access — one trust chain
to manage.

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

## Configuration: `deploy.local.yaml`

Lives at `tesseract-proxy-config/deploy.local.yaml` (gitignored via
`*.local.yaml`). All fields are optional — the binary starts without
the file; endpoints that need a missing field return `424 Failed
Dependency` with the list.

```yaml
# Publish flow (R6.3)
lightsail_ip: 13.207.35.97
ssh_key:    C:/Users/Sujoy/.ssh/lightsail.pem
signer_key: C:/Dev-wksp/sources/vs2022/equinomics/releases/keys/signing.key

# mTLS client material for the audit viewer (R7.0)
# Defaults derived from the workspace layout:
#   client_cert: .../releases/mtls/tesseract/client.pem
#   client_key:  .../releases/mtls/tesseract/client.key
#   client_ca:   .../releases/mtls/root-ca/ca.pem
#   proxy_port:  443
# client_cert: ...
# client_key:  ...
# client_ca:   ...
# proxy_port:  443

# Publish-flow defaults (rarely overridden):
# pubkey:        .../releases/keys/signing.pub
# bundle_out:    .../releases/staging/bundle.yaml
# sig_out:       .../releases/staging/bundle.yaml.sig
# proxy_repo:    .../src/tesseract-proxy
# reload_script: .../src/release/scripts/reload-bundle.sh
```

Missing-field policy:

- Publish (`POST /api/publish`) needs `lightsail_ip`, `ssh_key`,
  `signer_key`.
- mTLS endpoints (`/api/proxy/*`, `/api/audit/*`, `/api/log/*`) need
  `lightsail_ip` plus readable `client_cert` / `client_key` /
  `client_ca`. Missing → 424. Cert/key/CA are re-read on every call so
  rotation needs no restart.

## API

### Broker CRUD (R6.2)

| Method | Path                  | Body              | Notes |
|--------|-----------------------|-------------------|-------|
| GET    | `/api/brokers`        | —                 | List (id, display_name, enabled) |
| GET    | `/api/brokers/{name}` | —                 | Full profile |
| POST   | `/api/brokers`        | broker JSON       | id taken from body; 409 if exists |
| PUT    | `/api/brokers/{name}` | broker JSON       | body.id must equal `{name}` |
| DELETE | `/api/brokers/{name}` | —                 | 204 on success |

Every write validates against `schemas/bundle.schema.json`. Bad input
returns `400` with the validator error in `{"error": "..."}`.

### Publish + diff (R6.3 / R6.5)

| Method | Path           | Body / Query              | Notes |
|--------|----------------|---------------------------|-------|
| POST   | `/api/publish` | `{"confirm":"DEPLOY"}`    | Streams build+deploy log (chunked text). `412` on wrong phrase, `424` if deploy config missing, `409` if another publish is in flight. On success, snapshots `bundle.yaml` → `last-published.bundle.yaml` for future diffs. |
| GET    | `/api/diff`    | —                         | Builds a fresh bundle into a temp dir (mints a throwaway ECDSA key if `signer_key` is unset), returns `{current, previous, unified, no_previous}` as JSON. Pure-Go LCS unified diff. |

The frontend's publish modal calls `/api/diff` on demand so the
operator can preview the YAML change before typing `DEPLOY`.

### mTLS check (R7.0)

| Method | Path                | Notes |
|--------|---------------------|-------|
| GET    | `/api/proxy/check`  | 424 on missing config; 200 with `{subject, issuer, not_after, serial_hex, base_url, ca_file, cert_file}` of the loaded client cert. Does **not** call the proxy — that's `/api/proxy/health`. |

### Audit viewer (R7.1 – R7.6)

| Method | Path                 | Query / Body                  | Notes |
|--------|----------------------|-------------------------------|-------|
| GET    | `/api/audit/tail`    | `Last-Event-ID` header        | Opens upstream `GET /admin/audit/tail` SSE over mTLS, streams 1:1 to the browser. Browser `EventSource` auto-reconnects with the last record's `time` as `Last-Event-ID`; the proxy drains the in-memory ring strictly after that point so brief disconnects don't lose history (bounded by ring size, 256 by default). 502 on upstream dial failure. |
| GET    | `/api/audit/range`   | `?lines=N` OR `?since=&until=` (RFC3339Nano) | Historical scan of the on-disk JSON-lines log. Hard cap 10 000 records. Missing log file → 200 with empty body. |
| GET    | `/api/log/stat`      | —                             | `{path, size, mtime, exists}` of the audit log. |
| POST   | `/api/log/rotate`    | —                             | Force rotation. The proxy renames the current log to `<path>.<UTC timestamp>` and reopens at the original path; the rename + reopen is atomic w.r.t. concurrent writes (held under the same mutex). Returns `{rotated_to}`. |
| GET    | `/api/proxy/health`  | —                             | Proxies `/admin/healthz`. The frontend header polls this every 5 s. |

All audit endpoints return `424 Failed Dependency` with a missing-field
list when mTLS material isn't wired (`{"error":"mTLS not configured: …"}`)
and `502 Bad Gateway` on upstream dial / TLS failure.

## UI layout

Top header: `Tesseract (loopback admin)` · health badge (●/○ proxy) ·
tabs `[Brokers] [Audit log]`.

**Brokers tab**
- Sidebar list with `+ new` button.
- Main pane: per-broker editor (identity / endpoints table / idempotency /
  rate_limit). Dirty badge while unsaved. `Save` → `PUT`, `Delete` →
  `DELETE`, schema errors surfaced inline.
- Above the layout: `Publish to Lightsail…` button opens the publish
  modal with a `Preview diff` step before the `DEPLOY` confirmation.

**Audit log tab**
- Toolbar: `Pause/Resume`, `Load older`, `⇩ JSON` / `⇩ CSV` export
  (filtered set; CSV uses RFC-4180-ish quoting with a trailing
  `raw_json` column), `Clear`. Connection badge + drop-sentinel
  counter. Filtered/total record count on the right.
- Filter bar: outcome chips (`forward / reject / upstream_err` — match
  `audit.Outcome` in the proxy), broker dropdown (auto-populated from
  observed records), status prefix, free-text grep over
  `JSON.stringify(record)`.
- Table: newest-first, rows tinted by outcome.
- Bottom: collapsible `audit log retention` panel with path / size /
  mtime / `[Rotate now]` (with `confirm()`) / `[Refresh stat]`.

## Phase status

R6 — broker config
- R6.1 ✅ Go cmd skeleton + embed.FS + browser launch
- R6.2 ✅ Broker CRUD endpoints with schema validation
- R6.3 ✅ Publish flow (build + deploy with `DEPLOY` confirmation gate)
- R6.4 ✅ URL editor table UX (full per-broker form)
- R6.5 ✅ Diff preview before publish
- R6.6 ✅ Loopback-only enforcement (hard-fail)

R7 — audit log viewer (over mTLS, no SSH)
- R7.0 ✅ mTLS client wiring inside admin-ui
- R7.1 ✅ Live tail via SSE on the proxy
- R7.2 ✅ Historical pull (`/admin/audit/range`)
- R7.3 ✅ Filters (outcome / broker / status / free-text)
- R7.4 ✅ Export to CSV / JSON
- R7.5 ✅ Retention management (in-process rename+reopen)
- R7.6 ✅ Health probe (5 s poll, badge in header)

R8 — docs in progress.
