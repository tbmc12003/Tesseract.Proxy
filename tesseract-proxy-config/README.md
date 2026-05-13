# tesseract-proxy-config

Broker profile source-of-truth for the Tesseract order pass-through proxy
(arch §13.2 / §13.4).

Sibling Go module to `src/tesseract-proxy/`. The proxy binary does not
import anything from here — relationship is producer (this module emits
`bundle.yaml + .sig`) → consumer (proxy verifies + loads at boot). If
this is later split into its own GitHub repo, no code in either module
changes.

## Layout

```
src/
├── tesseract-proxy-config/             ← THIS DIRECTORY (content only — no Go code)
│   ├── meta.yaml                       # schema_version + min_proxy_version + issuer
│   ├── Makefile                        # `make bundle` invokes ../BuildScripts/build-bundle
│   ├── brokers/                        # one YAML per broker; merged in lex order
│   ├── schemas/bundle.schema.json      # JSON Schema for one broker entry
│   └── .github/workflows/validate.yml  # CI: schema-validate + dry-run build
└── BuildScripts/build-bundle/          # the merge+sign Go tool (Go module of its own)
    ├── main.go
    └── go.mod
```

## Workflow

1. Open a PR adding or modifying a `brokers/<id>.yaml`.
2. CI validates each broker against `schemas/bundle.schema.json` and runs
   a dry-run `make bundle` (skip-sign mode) to confirm the merged YAML
   parses against the proxy's strict loader.
3. On merge to `main`, CI bumps `bundle_version` (date + git short SHA),
   runs `make bundle` with the AWS-KMS-backed signer (P1.4), and
   publishes to `cfg.tesseract.in/bundles/` (P1.6).

## Building locally

```
make bundle BUNDLE_VERSION=2026-05-13-001 SIGNER=stub
```

The `SIGNER=stub` mode writes an Ed25519 signature using a local test key
(emits `bundle.yaml.sig`); the proxy's unit tests use the same approach.
The production `SIGNER=kms` mode calls `aws kms sign` against the pinned
Equinomics signing key (decision P0.4) — not used in development.

## Adding a broker

1. Drop `brokers/<broker_id>.yaml` matching the schema.
2. Verify endpoint paths against the broker's SDK (see arch §5; the
   convention is to read the installed Python SDK rather than the docs —
   docs lag).
3. Open a PR. CI does the rest.

The proxy itself does **no** broker-specific code: this bundle is the
*only* place broker shape lives. Adding a broker is a config change, not
a binary release.
