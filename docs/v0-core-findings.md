# Core V0 feasibility findings

2026-09-08. **Core V0 probes completed against the revised decoded-value contract;
no remaining material contradiction was found. V1 is not implemented or authorized
by these results.** Review the findings before starting V1.

## Scope and runtime

- Official Traefik **3.7.12**, bundled **Yaegi 0.16.1**, binary built with
  **Go 1.26.7**, darwin/arm64. The original archive checksum remains recorded in
  [the configuration findings](v0-findings.md).
- Native probe build/race/vet toolchain: **Go 1.27.0**, darwin/arm64. Probe modules
  declare Go 1.22; `go vet -stdversion` passed for the three core plugin modules.
  This is the explicit API-version analysis alternative in §9, not a claimed
  Go 1.22-toolchain execution or blanket Go 1.22 language-support guarantee.
- Actual Docker label provider and Redis KV provider were exercised with an
  isolated Redis container pinned to
  `redis@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf`.
  Docker discovery was constrained to the fixture's unique label, Redis used a
  unique root key, and listeners bound only to loopback. The container was removed.
- Plugins under `tests/v0/` are disposable observations, a synthetic config
  overlay, and finite concurrency probes. They are not the V1 resolver, provider
  presets, feed poller, cache subsystem, or a deployable middleware.
- No CrowdSec log-parser spike, bouncer/AppSec integration, or V1 full-chain
  compatibility suite was implemented. Those are outside this phase.

## Results

| V0 area | Verified result |
|---|---|
| Typed configuration boundary | Prior 23-case probe established recursive `,remain`, null-as-omission, and lossy empty-container conversions. The revised contract accepts that boundary. |
| Decoded validation and overlay | 25 cases passed through actual Traefik/Yaegi: unknown keys/presets/modes, empty decoded lists, duration parsing, decimal minimum counts and invalid fractional/signed/padded/exponent/overflow/range forms. Synthetic preset omission inherits, non-empty lists replace, and a supplied predicate adds alongside inherited members. Input is unchanged. |
| Provider forms | 8 Docker/Redis checks passed: indexed sources/feeds and decimal strings arrive; unknown nested keys and fractional minima fail construction; empty-value behavior differs as documented below. |
| Shared construction and primitives | Two actual routers use one middleware. Each served observation additionally calls interpreted `New` eight times concurrently; each construction makes 24 concurrent independent config copies/acquisitions. Identical keys share one registry entry; changing URL, format, interval, minimum or cache directory gives a separate entry, total six. Nested borrowed input is unchanged. |
| Publication APIs | Yaegi executes mutexes, goroutines, `atomic.Value`, and `map[netip.Addr]` / `map[netip.Prefix]` lookups. Initialized snapshots and a finite four-publication loop succeed. Canceling an unrelated construction context does not own that loop. Native concurrent `New` calls pass `go test -race`. |
| Header boundary and ordering | Secure stripping and insecure preservation match §2. Missing X-Real-Ip/XFP are synthesized. A synthesized X-Real-Ip preempts a later informative input; reversing order selects the informative input. Invalid earlier extraction permits the later input. |
| Connection nominations | Identity and selector inputs disappear without allowlisting. Allowlisting preserves them to the plugin, while the backend loses nominated inputs. Tests demonstrate later-source selection and Connection-induced peer fallback. |
| Placement | Entrypoint default executes before the child matcher, but after root matching. Root ClientIP sees the original peer; child ClientIP sees the rewritten identity. Child-default 404 and internal ping execute the default. Entrypoint-unmatched 404 does not. |
| Early rejections | Explicit encoded-slash denial gives 400 before the plugin; conflicting SNI/Host TLS options give 421 before the plugin. |
| PROXY boundary | Trusted PROXY v1 advertising `0.0.0.0:0` reaches the plugin exactly and remains valid peer fallback. PROXY v2 LOCAL retains `127.0.0.1:<socket port>`. |
| TLS and streaming | Pure request mutation preserves TLS pointer identity and exported connection state. HTTP/1.1 and native HTTP/2 deliver the first response chunk before the backend is released to send the second. WebSocket upgrade and masked client frame/echo work through the mutation fixture. |
| Backend and access log | Deleting XFF causes Traefik to append the rewritten RemoteAddr host for the backend. Buffered logs capture changed request headers but original core client fields. Exact entrypoint field is `entryPointName`. Coverage assertions include child 404, unmatched, internal ping, 400 and 421. |

There are **33 runtime assertions** in the final runtime evidence. These are
feasibility/contract observations, not a replacement for the extensive V1 tests
listed separately in §9. In particular, the fixture's ordered bare-IP extraction
is not the full resolver. The finite publication loop has no network/cache I/O;
production polling, reload lifetime, cache loading, LKG and worker churn remain V1
implementation tests. Streaming here is HTTP/1.1, HTTP/2 and WebSocket, not the
future native-gRPC/bouncer/AppSec full-chain suite. TLS preservation does not
claim a full mutual-TLS certificate-policy integration test.

## Demonstrated provider syntax and limitations

Docker labels use bracket indices and dots; for example (the preset is deliberately
synthetic and exists only in this probe):

```text
traefik.http.middlewares.docker-good.plugin.probe.sources[0].name=probe
traefik.http.middlewares.docker-good.plugin.probe.sources[0].preset=v0
traefik.http.middlewares.docker-good.plugin.probe.sources[0].trust.feeds[0].url=https://example.invalid/feed
traefik.http.middlewares.docker-good.plugin.probe.sources[0].trust.feeds[0].format=lines
traefik.http.middlewares.docker-good.plugin.probe.sources[0].trust.feeds[0].refreshInterval=1s
traefik.http.middlewares.docker-good.plugin.probe.sources[0].trust.feeds[0].minEntries=1
```

Redis KV uses slash-separated numeric indices under its configured root key:

```text
<root>/http/middlewares/redis-good/plugin/probe/sources/0/name = probe
<root>/http/middlewares/redis-good/plugin/probe/sources/0/preset = v0
<root>/http/middlewares/redis-good/plugin/probe/sources/0/trust/feeds/0/url = https://example.invalid/feed
<root>/http/middlewares/redis-good/plugin/probe/sources/0/trust/feeds/0/format = lines
<root>/http/middlewares/redis-good/plugin/probe/sources/0/trust/feeds/0/refreshInterval = 1s
<root>/http/middlewares/redis-good/plugin/probe/sources/0/trust/feeds/0/minEntries = 1
```

The complete real label and KV fixtures, including router attachment, are saved
in [labels.json](../tests/v0/evidence/core/providers/labels.json) and
[kv.json](../tests/v0/evidence/core/providers/kv.json). File-provider fixtures use
JSON-form YAML, as in the earlier adapter probe. No other provider syntax is
claimed as tested.

A Docker label `...trust.static=` reaches typed decoding as an empty list and is
rejected by the V0 decoded validator. The Redis key with a zero-length value is
omitted before `New`: decoded trust is nil and the synthetic preset is inherited.
This is omission under §3, **not** a clear operation and not a decoded empty list.
The initial provider fixture incorrectly expected both paths to reject; it was
corrected after inspecting Redis's provider configuration event. No plugin-owned
coercion was added. Non-empty valid decoded forms, rather than original provider
bytes, remain the contract.

The config fixture only implements the V0 validation branches exercised here;
it is not complete production schema validation. Its `minEntries` path expects
the strings actually received from these providers. Acceptance of other providers'
retained numeric types still requires the V1 field-specific conversion code/tests.

## Access-log observations

For the request supplying forged XFF `203.0.113.99` and selecting `198.51.100.2`:

- Backend XFF is `198.51.100.2`, synthesized from rewritten RemoteAddr.
- Log `request_X-Real-Ip` is `198.51.100.2` and request XFF is absent after deletion.
- Log `ClientAddr` is the original `127.0.0.1:<port>` and `ClientHost` is
  `203.0.113.99`, derived before mutation. Core fields do not follow RemoteAddr changes.
- The entrypoint field is `entryPointName`, including on unmatched and rejected paths.
- Child-default 404 and ping logs contain the fixture's execution observation.
  Entrypoint-unmatched 404 lacks RouterName and the observation; encoded/SNI
  rejection logs also lack that observation.

Logs used `bufferingSize: 10` and were checked after graceful shutdown flushed the
buffer. Test-only `X-V0-*` headers identify observations; they do not introduce
an execution-marker feature or prove authenticity of production log fields.
No optional log-parser attribution or detection decisions were tested.

## Fixture corrections, not contract changes

- Traefik 3.7.12 permits encoded slashes by default. The denial fixture explicitly
  sets `http.encodedCharacters.allowEncodedSlash: false`, as required to test
  rejection ordering. Serialized log paths use uppercase `%2F`; the assertion
  was corrected to that spelling.
- `reflect.DeepEqual` reports unequal TLS connection-state copies because the
  state contains a private non-nil function. The observation instead checks
  unchanged pointer identity and a snapshot of exported state around mutation.
- Redis's zero-length omission is recorded above. The revised decoded-value
  contract already accounts for values dropped before construction.

These corrections did not require changing the Realclient architecture or adding
workarounds to resolver behavior.

## Reproduction and evidence

From the repository root, using the verified pinned binary:

```sh
python3 tests/v0/config.py --traefik /absolute/path/to/traefik --output /tmp/v0-config
python3 tests/v0/primitives.py --traefik /absolute/path/to/traefik --output /tmp/v0-primitives
python3 tests/v0/providers.py --traefik /absolute/path/to/traefik --output /tmp/v0-providers
python3 tests/v0/runtime.py --traefik /absolute/path/to/traefik --output /tmp/v0-runtime
(cd tests/v0/primitives-plugin && go test -race ./...)
(cd tests/v0/primitives-plugin && go vet -stdversion ./...)
(cd tests/v0/config-plugin && go vet -stdversion ./...)
(cd tests/v0/runtime-plugin && go vet -stdversion ./...)
```

Python 3, Go, OpenSSL, loopback socket permission and the pinned Traefik binary are
required. The provider probe additionally needs Docker and the pinned Redis image
(`docker pull redis@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf`).
The runtime probe compiles a dependency-free Go HTTP/2 client into a temporary
directory. Probe processes and the container are cleaned up; evidence is retained.

Checked-in evidence:

- [Decoded config results](../tests/v0/evidence/core/config/boundary.json)
- [Primitive results](../tests/v0/evidence/core/primitives/boundary.json)
- [Provider results](../tests/v0/evidence/core/providers/results.json)
- [Runtime assertions](../tests/v0/evidence/core/runtime/results.json)
- [Buffered access log](../tests/v0/evidence/core/runtime/access.jsonl)
- [Tool/runtime verification](../tests/v0/evidence/core/verification.json)

Each evidence subdirectory also contains the corresponding Traefik log and
supplied configuration where applicable. All identities/feeds are synthetic;
no feed URL is fetched. HTTP 404 on an invalid-config case is corroborated by
construction errors in the corresponding runtime log, not interpreted alone.
