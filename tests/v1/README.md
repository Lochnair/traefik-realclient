# V1 Traefik-runtime integration suite

Exercises the committed `github.com/Lochnair/traefik-realclient` package as a
real Traefik **local plugin**, interpreted by the bundled Yaegi — not native Go
handler tests. Complements the native `go test` suite and the `tests/v0/`
feasibility probes.

## Running

```sh
python3 tests/v1/run.py --traefik "$(which traefik)" --output /tmp/v1
# or an individual suite:
python3 tests/v1/core.py --traefik "$(which traefik)" --output /tmp/v1/core
```

Requires: Python 3, Go (builds the streaming probes), OpenSSL, loopback socket
permission, and **Traefik 3.7.12** (Yaegi 0.16.1). `crowdsec.py` / `appsec.py`
additionally need Docker + network; `certs.py` / `badger.py` need network to
fetch third-party plugin source.

## Pinned third-party versions

| Component | Version | Notes |
|---|---|---|
| Traefik | 3.7.12 (Yaegi 0.16.1) | host build was Go 1.27; findings unchanged |
| `maxlerebourg/crowdsec-bouncer-traefik-plugin` | v1.7.1 | local plugin, vendored deps |
| `crowdsecurity/crowdsec` (LAPI + AppSec) | v1.6.4 | disposable container |
| `smerschjohann/mtlswhitelist` | v0.3.0 | matches Appendix A `iprange.go` |
| `fosrl/badger` | v1.7.0 | == Appendix A commit `926d126` |
| `google.golang.org/grpc` (test client) | v1.62.1 | `grpcprobe` only |

## Suites

| Suite | Covers (§9) |
|---|---|
| `core.py` (30) | Yaegi load, secure/insecure stripping, entrypoint-default placement + child inheritance + early rejection, backend-observed canonical `X-Real-Ip`/XFF/`RemoteAddr`/scheme/forwarding headers, Traefik XFF append + instance joining, `aliasHeadersStrategy: delete`, IPv4/IPv6/mapped, `X-Forwarded-Server` preserved, scheme aliases, HTTP-over-TLS-origin port vs stock, delegated XFCC preserved, HTTP/1.1 streaming, multi-source cross-deletion, duplicate extraction header |
| `streaming.py` (3) | native HTTP/2 + WebSocket data + native gRPC bidi streaming with resolved identity and trailers |
| `certs.py` (6) | mtlswhitelist certificate branch and no-certificate IP-range branch on canonical `X-Real-Ip`; Traefik `passTLSClientCert` after Realclient (forged assertions cleared, real `req.TLS` republished) |
| `crowdsec.py` (5) | real CrowdSec LAPI bouncer: banned resolved client blocked, another allowed, fallback enforced on the peer, forged XFF ignored |
| `appsec.py` (4) | real CrowdSec AppSec: attack blocked end-to-end, clean allowed, alert attributed to the resolved IP |
| `badger.py` (6) | `fosrl/badger` with the documented config uses the normalized address, does not rebuild XFF, forwards no CDN channel; denies/falls back on the resolved identity |
