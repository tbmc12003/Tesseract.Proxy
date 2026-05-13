# tesseract-proxy-egress

The companion nftables-egress helper for the Tesseract proxy (arch §7.6,
§13.3, P1.3). It reads the active broker bundle, resolves each broker
host to its current IP set, and applies an nftables ruleset that allows
outbound TCP/443 *only* to those IPs.

This binary runs as a separate systemd unit with `CAP_NET_ADMIN`. The
proxy itself runs without elevated capabilities; the privilege boundary
is exactly here.

Sibling Go module to `src/tesseract-proxy/`. Does **not** import the
proxy's `internal/egress` — the helper is a separate trust boundary and
keeps its own copy of the renderer (~30 LOC). Drift risk is real but not
currently CI-enforced — see the *Drift* section below.

## Why a separate binary

Two reasons:

1. **Privsep:** the proxy binary needs no `CAP_NET_ADMIN` if a separate
   privileged helper does the firewall work. Compromise of the proxy
   doesn't get firewall mutation.
2. **Deployment shape:** the egress ruleset is host policy, not request
   policy. It outlives any single proxy process and can be re-applied
   on boot before the proxy starts.

The proxy's own `internal/egress` package does the same logic in-process
for dev / single-binary setups where privsep isn't needed; this helper
is the production deployment path.

## Usage

```
tesseract-proxy-egress \
    --bundle    /etc/tesseract-proxy/profiles/bundle.yaml \
    --apply                                 # actually run `nft -f -`
```

Without `--apply`, the rendered ruleset is printed to stdout (handy in
CI / dry runs).

## Layout

```
tesseract-proxy-egress/
├── README.md
├── go.mod
└── main.go             # ~150 LOC; stdlib + yaml.v3
```

The rendering logic is a deliberate copy of `internal/egress.Render` in
`src/tesseract-proxy/internal/egress/egress.go` (~30 LOC). They drift
independently on purpose — the helper is a separate trust boundary and
must not import the proxy's `internal/` (Go would forbid it anyway).

## Drift (current posture: manual)

There is currently **no automated drift check** between the two renderers.
The two implementations diverging is a real risk: a change to the proxy's
internal renderer wouldn't fail CI here, and the production nftables
ruleset could end up shaped differently from what unit tests in the proxy
verify.

Mitigations on the to-do list, in order of cost:

1. Add a CI step that builds both, generates a sample bundle, pipes through
   each renderer, and `diff`s the output. Cheap; ~10 lines of YAML in
   `.github/workflows/ci.yml`. **Not yet in place.**
2. Refactor to share a tiny `renderer` package both modules can import
   (would require pulling the renderer out of `internal/` in the proxy
   module — slightly weakens the boundary).

Option 1 first if/when drift bites.
