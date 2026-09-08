# V1 Traefik-runtime integration findings

2026-09-08. **The committed V1 plugin was exercised end-to-end through the real
Traefik 3.7.12 / Yaegi 0.16.1 runtime and the documented downstream
integrations. No contradiction with `docs/design.md` or
`docs/v0-core-findings.md` was found.** Harness and evidence live under
`tests/v1/`.

## Scope and runtime

- Official **Traefik 3.7.12** (`traefik version` → `3.7.12`, codename cheddar),
  Homebrew build, `darwin/arm64`. This binary reports `Go version: go1.27.0`;
  `docs/v0-core-findings.md` recorded a `go1.26.7` build. Yaegi is 0.16.1 in
  both (source-pinned in Traefik 3.7.12). The plugin loaded and every runtime
  assertion held; the host toolchain version did not change any finding. The
  native `go vet -stdversion` (Go 1.22) check still gates the API surface.
- The plugin is loaded as a Traefik **local plugin**
  (`plugins-local/src/github.com/Lochnair/traefik-realclient`) from the
  committed `.go` sources, i.e. interpreted by Yaegi, not compiled natively.
- Third-party components are pinned in `tests/v1/README.md`. CrowdSec runs in a
  disposable container; other plugins are loaded as local plugins from tagged
  source.

## Results (62 checks across 7 suites, all passing)

| Area | Verified |
|---|---|
| Yaegi load | The real package — `reflect`-based decoded-config validation, preset overlay, `atomic.Value` snapshots, the feed-worker registry and its background goroutine, `crypto/sha256` cache ids — interprets and runs under Yaegi 0.16.1 with no shims. |
| Feed subsystem | The interpreted worker fetches a real HTTPS feed, parses/validates it, publishes the snapshot, and writes + reloads the schema-versioned disk cache. A 304 keeps the set; a valid update is adopted; an invalid 200 and a 503 both retain last-known-good; a restart with the origin down serves from the persisted cache. Matches §6. (Traefik's release build sets `DefaultGODEBUG=x509sslcertoverrideplatform=0`, so the macOS test overrides it to let `SSL_CERT_FILE` trust the local feed CA — the plugin itself does normal certificate validation.) |
| Secure vs insecure | Secure entrypoint strips a forged `X-Real-Ip` and the plugin then resolves the peer; insecure entrypoint preserves the supplied value for extraction. Matches §2.2. |
| Placement | Entrypoint-default middleware runs after root routing (root `ClientIP` sees the peer, a `198.51.100.2` root rule 404s) and before the child muxer (child `ClientIP` sees the rewrite); child-default 404 still runs the plugin; entrypoint-unmatched 404 and encoded-slash denial precede it. Matches §2.1. |
| Backend-observed identity | Backend sees exactly one canonical `X-Real-Ip` = effective; `Forwarded`, `Cf-Connecting-Ip`, `True-Client-Ip`, `X-Client-Ip` and underscore aliases removed; provider metadata (`Cf-Ipcountry`, `Cdn-Pullzoneid`) preserved; `Cf-Visitor` removed. |
| XFF | Realclient deletes inbound XFF; Traefik's proxy appends the effective `RemoteAddr` host, so the backend sees a single effective entry. Multiple inbound XFF instances (Traefik-joined) collapse to that one entry. |
| `aliasHeadersStrategy: delete` | A dotted/underscore `X_Real_Ip` alias is dropped before the backend; combined with the plugin's own alias sweep. |
| Address families | IPv4, IPv6 and IPv4-mapped IPv6 extraction all produce the canonical unmapped form and a `client:0` `RemoteAddr`. |
| Scheme | Resolved independently of peer TLS; `X-Forwarded-Scheme` and `X-Scheme` are always rebuilt to match canonical `X-Forwarded-Proto`, where a side-by-side stock Traefik run emits no `X-Forwarded-Scheme`. WebSocket upgrade yields `ws`/`wss`. |
| `X-Forwarded-Server` | Traefik's synthesized value is preserved (identical to the stock path). |
| Forwarded port | Original HTTP over a TLS-origin connection with no explicit `Host` port emits `X-Forwarded-Port: 80` where stock Traefik's transport fallback would emit 443 (§5.2). |
| Certificate headers | Inbound `X-Forwarded-Tls-Client-Cert(-Info)` cleared; delegated Envoy/Istio `X-Forwarded-Client-Cert` preserved. Downstream `passTLSClientCert` republishes the real `req.TLS` cert + subject CN after Realclient. |
| Streaming | HTTP/1.1 chunked, ALPN-negotiated HTTP/2, WebSocket masked-frame echo, and native gRPC bidirectional streaming (interleaved messages, clean `grpc-status 0` trailer) all pass through with the resolved identity; the first response chunk is observed before the backend is released. |
| CrowdSec bouncer | With `forwardedHeadersCustomName: X-Forwarded-For` and empty trust pools, the bouncer sees no XFF at middleware time and enforces on `RemoteAddr` = the rewritten effective IP: a LAPI-banned resolved client is blocked, another allowed, a malformed-identity request is enforced on the peer (allowed clean, blocked once the peer is banned), and a banned IP in a forged XFF does not change the verdict. Matches §7.2 / Appendix A. |
| CrowdSec AppSec | A `.env` probe is blocked end-to-end (403), a clean request passes, and the AppSec alert's `source.value` is the Realclient-resolved IP (bouncer `X-Crowdsec-Appsec-Ip` = rewritten `RemoteAddr`). |
| Badger | `fosrl/badger` v1.7.0 loads under Yaegi (its `go 1.25` module directive notwithstanding). With `disableDefaultCFIPs: true`, `trustip: []`, `customIPHeader: ""` it reports the Realclient-resolved IP to Pangolin, ignores forged `Cf-Connecting-Ip`/XFF, does not rebuild XFF, forwards no CDN identity channel, and enforces/falls back on the resolved identity. Matches §7.2 / Appendix A. |
| mtlswhitelist | v0.3.0 IP-range branch accepts/denies on the canonical `X-Real-Ip`; the certificate branch still admits an out-of-range client with a valid cert, confirming `req.TLS.PeerCertificates` is untouched. |

## Assumptions newly validated

- The full `reflect` / `atomic.Value` / goroutine / `crypto` surface used by the
  committed V1 package is interpretable by the shipped Yaegi, not just by V0's
  narrower probes.
- Traefik appends XFF **after** the middleware chain, so a request-time bouncer
  in that chain genuinely falls back to the Realclient-set `RemoteAddr` — the
  core premise of the §7.2 CrowdSec recipe.
- `passTLSClientCert` placed after Realclient regenerates certificate headers
  from real `req.TLS` state, so clearing the inbound assertions is safe.
- Badger v1.7.0's `go 1.25` go.mod directive does not block loading in Traefik
  3.7.12 (the code uses no post-1.22 language/stdlib features that Yaegi rejects).
- The interpreted feed worker's full path — background goroutine, bounded HTTPS
  fetch, `If-None-Match`/ETag handling, `atomic.Value` publication, temp-file +
  rename disk cache, and cache reload on start — runs under Yaegi 0.16.1, not
  just the narrower `atomic`/goroutine primitives V0 probed.

## Assumptions contradicted

None.

## Reproduction

```sh
python3 tests/v1/run.py --traefik "$(command -v traefik)" --output /tmp/v1
```

Needs Python 3, Go, OpenSSL, Docker + network (CrowdSec suites) and Traefik
3.7.12. Per-suite result JSON, the Traefik log and (for CrowdSec) container
logs are written under the output directory.
