# traefik-realclient — design & implementation plan

**Dynamic trusted-proxy client IP resolution for Traefik.**

| | |
|---|---|
| Repository / module | `traefik-realclient` |
| Traefik plugin & config key | `realclient` |
| Status | **Design complete; not implemented.** No code, repository, branch or production config exists. |
| Document date | 2026-09-07 |

This document is self-contained: it carries its own evidence, the measurements behind each
decision, and a list of earlier conclusions that were found to be wrong so they are not
re-derived. Every upstream claim is cited to a file and line in §0.

---

## Problem statement and scope

> A provider-agnostic Traefik middleware for dynamically establishing trust in upstream
> proxies/CDNs, resolving their authoritative client identity, and normalizing the request so that
> downstream middleware can consistently use `RemoteAddr` and canonical headers without knowing
> provider-specific topology.

**The problem is dynamic upstream trust.** Traefik's only native mechanism for trusting an upstream
proxy is `entryPoints.*.forwardedHeaders.trustedIPs`, which lives in **static configuration** and
therefore cannot track a trusted-peer set that changes without a restart. Everything else in this
document follows from that gap.

Bunny is the motivating provider because it publishes ~900 **individual edge addresses** (586 IPv4
+ ~300 IPv6, F9) that change relatively often — precisely the shape static configuration handles
worst. Cloudflare is the easy case by contrast: 22 stable CIDRs and a provider-specific header that
Traefik does not strip. **Cloudflare could reasonably be configured statically today.** It is in
scope to prove the abstraction is genuinely provider-agnostic, not because it needs solving.

Multiple simultaneous providers on one Traefik instance are a first-class goal:

```
site A -> Bunny        site D -> direct
site B -> Bunny        site E -> another trusted proxy
site C -> Cloudflare
```

The architecture is therefore an ordered list of generic `{ trust, extract }` sources:

```
establish that the immediate peer is a trusted upstream
            ↓
apply that source's extraction strategy
            ↓
normalize effective client identity
```

Bunny and Cloudflare are **presets over generic mechanisms**, never separate request-processing
code paths. Provider-specific header names are a secondary concern — a parameter of `extract`, not
a reason for the project.

Two things that are *consequences*, not motivations, and should be read as such:

- **Bunny's choice of `X-Real-IP`** collides with Traefik's forwarded-header handling (F1) and
  forces the posture decision in §2. It is an implementation obstacle, not the root problem.
- **Binding requests to *our* Bunny account** (§9.4) is a residual threat with several optional
  mitigations. It must not drive v1 complexity. Feed-only trust is the accepted baseline for this
  personal/homelab deployment.

---

## 0. Evidence base

| Component | Version inspected |
|---|---|
| Traefik | `master` (2026-09-07) |
| crowdsec-bouncer-traefik-plugin | `04d9288` (2026-09-05) |
| crowdsecurity/hub `parsers/s01-parse/crowdsecurity/traefik-logs.yaml` | `master` (2026-09-07) |
| fosrl/badger | `926d126` (2026-08-24) |
| smerschjohann/mtlswhitelist | `HEAD` (2026-09-07) |
| Bunny origin behaviour | **measured directly** via Edge Script echo app + disposable Pull Zone |
| Bunny / Cloudflare feeds | probed live |

### 0.1 Conclusions that were found to be wrong — do not re-derive these

Earlier drafts of this design reached the following conclusions. Each was overturned by
measurement or by reading upstream source. They are recorded so a fresh reader does not
independently re-derive them.

**Factual corrections (superseded by measurement):**

| Earlier claim | Correction |
|---|---|
| "Bunny's `X-Forwarded-For` is `CDN-IP, user-IP`" | **Wrong** — it contains only the real client IP (F11). The original came from a search summary, not a primary source. |
| "Unresolved: does Bunny overwrite or append a client-supplied `X-Real-IP`?" | **Resolved** (F11): Bunny overwrites, including duplicate header instances. Ordinary clients cannot spoof identity through Bunny. |
| "`hostExact` on `CDN-Host` rests on two unmeasured properties" | **One measured, positive** (F16): hostname → Pull Zone is globally unique; re-registering an in-use hostname on a second zone is rejected. One property remains untested (§9.4). |
| "Must test whether Bunny overwrites `X-Real-IP`" | **Done** (F11). |
| "`hostSuffixes` over custom domains is a recommended default with real security value" | **Wrong** (F16): Bunny attaches custom hostnames with no DNS verification, so suffix matching is not ownership proof. Demoted to an explicitly-weak optional predicate (§4.2). |

**Design conclusions that were reversed:**

| Earlier conclusion | Correction |
|---|---|
| `hostSuffixes` removed entirely as "dead as a security control" | **Too absolute.** Restored (§4.2) as optional *weak defence in depth*, never described as authentication. |
| Posture A (secure entrypoint) preferred on security grounds | **Reversed** (§2). F11 removed A's security advantage; posture B is recommended, conditional on the §8 access-log fix. |
| "The shared secret is the only thing binding *from Bunny* to *from my Bunny*" | **Softened** (§9.4). Still the strongest binding, but a residual threat accepted for this deployment — not a design driver. |
| Document framed around Bunny's `X-Real-IP` choice and account-binding | **Reframed.** The root problem is dynamic upstream trust vs. Traefik's static `forwardedHeaders.trustedIPs` (see Problem statement). Bunny's header choice is an obstacle (F1); account-binding is a residual threat. |
| Cloudflare implicitly presented as needing this plugin | **Clarified.** Its 22 stable CIDRs could be configured statically today; it is in scope to prove genericity. |
| `CDN-*` metadata must be stripped on the direct/non-provider path | **Withdrawn** (§6.3). Out of scope — those headers already pass through Traefik today. |
| Every header any `trust` predicate read should be deleted | **Wrong** (§6.2). Deletion is by header *role*: identity removed and canonicalized, `headerEquals` secrets stripped after use, provider metadata read by `headerIn`/`host*` left untouched. |
| "`CDN-*` predicates are only meaningful ANDed with a peer-address predicate" | **Reframed as Bunny guidance, not a rule** (§4.1, §6.3). Any predicate may stand alone; the plugin does not police combinations. |
| Pull Zone ID allowlisting expressed as `hostExact` | **Split** (§4.1.1). Raw-byte predicates (`headerEquals`/`headerIn`) are separate from DNS-normalized ones (`hostExact`/`hostSuffixes`). |
| `trust` implicitly required a peer-address or secret anchor | **Corrected** (§4.1). Any single predicate suffices; at least one required; all configured must hold; no boolean DSL. |
| Rejected requests set `X-Real-Ip` to the peer "so the event is attributable" | **Changed** (§7, §8.2). Rejections leave it unset so the log path drops the event instead of attributing it to a POP. |
| CrowdSec log parser should "fall back otherwise" to `ClientHost` | **Never** (§8.2). `ClientHost` is pre-middleware and client-influenced. |
| …and its successor: "drop every event lacking `request_X-Real-Ip`" | **Also wrong** — it would blind probe detection. F18 shows unmatched requests are distinguishable; the rule is three-way (§8.2). |
| `:0` presented as the correct `RemoteAddr` port | **Softened** (§6.1). The invariant is valid `host:port`; `:0` is a cleanliness preference. |
| Retain the observed peer port when normalizing | **Changed** to `:0` (§6.1) — the hybrid client-IP + POP-port tuple is what the HAProxy design deliberately avoided. |
| Three-layer feed cold start, shrink heuristics, configurable prefix floors, backoff curve | **Trimmed** out of v1 (§5). |

**Not superseded:** F1's core conclusion. Bunny's identity headers are `X-Real-IP` and
`X-Forwarded-For`; both are Traefik-managed and both are still stripped before any plugin runs.
The correction to XFF's *contents* does not change the blocker.

---

## 1. Findings

### F1 — Traefik destroys Bunny's client IP before any plugin runs, and replaces it with the POP IP

- `pkg/config/static/entrypoints.go:87` — `ep.ForwardedHeaders = &ForwardedHeaders{}`; zero value
  is `Insecure=false, TrustedIPs=nil`.
- `pkg/middlewares/forwardedheaders/forwarded_header.go`:
  ```go
  if !x.insecure && !x.isTrustedIP(r.RemoteAddr) { DeleteXForwardedHeaders(r.Header) }
  ```
  `isTrustedIP` returns false whenever `ipChecker == nil`, i.e. whenever `trustedIPs` is unset.
- `XHeadersSet` contains **both** `X-Real-Ip` and `X-Forwarded-For` (and `_`-variants).
- `rewrite()` then sets `X-Real-Ip` to the socket peer when empty.

Bunny sends the end-user IP in **both** `X-Real-IP` and `X-Forwarded-For` (§F11). Under a stock
entrypoint, Traefik deletes both and re-sets `X-Real-Ip` to the **Bunny POP address** — exactly
the value we must not treat as the client.

*Framing note:* this is an obstacle to work around, not the project's reason for existing. A
provider that used a non-managed header (as Cloudflare does) would sidestep F1 entirely and still
need everything else in this document. The root problem remains dynamic trusted-peer discovery.

Survivors (never touched by Traefik): `Forwarded`, `CF-Connecting-IP`, `True-Client-IP`,
`CF-Visitor`, `X-Client-IP`, **and Bunny's entire `CDN-*` namespace**. So Cloudflare works out of
the box; Bunny does not.

### F2 — entrypoint default middlewares are prepended to every root router

`pkg/server/aggregator.go:362` — `cp.Middlewares = append(m.Middlewares, cp.Middlewares...)`.
`entryPoints.<ep>.http.middlewares` (static config) is prepended to every root router on that
entrypoint, including routers Pangolin / Middleware Manager generate dynamically. This is what
makes a guaranteed-first normalizer possible without touching Middleware Manager, and is the
precondition for posture B being defensible.

Caveat: `aggregator.go:330` skips routers with `ParentRefs != nil` (child routers). Confirm
Pangolin emits none.

### F3 — backend-facing XFF is appended by the proxy, after all middlewares, from `RemoteAddr`

`pkg/proxy/httputil/proxy.go:70-81`. Rewriting `req.RemoteAddr` therefore yields a correct
backend-facing `X-Forwarded-For` for free, and deleting inbound XFF gives backends a clean
single-entry chain.

### F4 — `RemoteAddr` must remain valid `host:port`, or CrowdSec bans everything

CrowdSec `pkg/ip/ip.go:124` → `net.SplitHostPort`; on error `bouncer.go:345` calls
`handleBanServeHTTP(..., ReasonTECH)`. A bare IP in `RemoteAddr` would ban 100% of traffic.

### F5 — CrowdSec **bouncer** IP resolution (request-time)

`bouncer.go:343` → `ip.GetRemoteIP(req, serverPoolStrategy, forwardedCustomHeader)`. Defaults:
header `X-Forwarded-For`, trusted pool empty. `PoolStrategy.getIP` walks the header right-to-left
and returns the first entry not in the (empty) pool — i.e. the **rightmost XFF entry**. It falls
back to `RemoteAddr` **only when the header is absent or entirely empty**.

⇒ Delete inbound XFF and the bouncer uses `RemoteAddr` with zero CrowdSec configuration. AppSec
uses the same resolved value (`bouncer.go:492`). `clientTrustedIPs` is a separate bypass check on
the resolved client and is correctly unrelated to CDN trust.

### F6 — Badger IP resolution, and a real hazard

`main.go:491-512`: `isTrustedIP(RemoteAddr)` against `trustIP`; if trusted and `CF-Connecting-IP`
present, use it; else `SplitHostPort(RemoteAddr)`. `main.go:179-187`: when `DisableDefaultCFIPs`
is false (**the default**) Badger loads hardcoded Cloudflare CIDRs into `trustIP`.

Post-normalization `RemoteAddr` is the real client. A client inside Cloudflare's ranges —
Cloudflare WARP egresses exactly there — enters Badger's trusted branch. Deleting
`CF-Connecting-IP` on the direct path neutralizes it. Concrete justification for sanitizing
direct traffic too.

### F7 — mtlswhitelist depends on `X-Real-Ip` with no `RemoteAddr` fallback

`iprange.go:49-51` reads `X-Real-Ip`, falls back to `X-Forwarded-For`, `net.ParseIP`s it, and
denies on nil. Deleting `X-Real-Ip` without re-setting it fails every IP-range rule closed.
Setting canonical `X-Real-IP` is mandatory. Its mTLS path (`mtlsOrWhitelist.go:173`) reads
`req.TLS.PeerCertificates`, untouched by this design.

### F8 — plugin lifecycle / Yaegi

`pkg/plugins/middlewareyaegi.go`: `interp.New` + `i.Use(stdlib.Symbols)` — **one interpreter per
plugin name**, full stdlib including `net`, `net/http`, `net/netip`, `sync`, `sync/atomic`,
`time`, `encoding/json`, `os`. `Builder.Build` → `newMiddleware(config)` → `NewHandler(ctx,next)`,
both re-run on **every dynamic config reload**. Config decode is `mapstructure` with
`WeaklyTypedInput: true`.

Consequences: package-level globals are shared across all instances (the basis for the shared
feed registry); there is **no shutdown hook** (`pluginMiddleware` exposes only `NewHandler`), so
refcounted teardown is not implementable; `New()` must be idempotent and cheap; avoid generics
(`atomic.Pointer[T]`); the per-request path runs interpreted and must stay trivial. Precedent:
the CrowdSec plugin already uses package globals, `go func()`, tickers and `sync/atomic` in
production under Yaegi.

### F9 — feed shapes (probed live)

| Feed | URL | Format | Content |
|---|---|---|---|
| Bunny v4 | `api.bunny.net/system/edgeserverlist/plain` | lines, **ETag** | 586 bare IPv4 **addresses** |
| Bunny v6 | `api.bunny.net/system/edgeserverlist/ipv6` | JSON array (even with `?plain=true`) | ~300 bare IPv6 addresses |
| CF v4 | `www.cloudflare.com/ips-v4` | lines | 15 CIDRs |
| CF v6 | `www.cloudflare.com/ips-v6` | lines | 7 CIDRs |

Bunny is ~900 exact hosts; Cloudflare is 22 prefixes. Hence the hybrid
`map[netip.Addr]struct{}` + `[]netip.Prefix` structure. Parser keys off configured format, not
content-type sniffing.

### F10 — access log: `Core` fields are frozen at entry, header fields are live

This is the distinction that resolves the CrowdSec log problem, and it is easy to get half right.

- `pkg/middlewares/accesslog/logger.go:197-207` — at entry, `core` is populated and
  `Request.headers` is set to **`req.Header` itself, a live map reference, not a copy**.
- `logger.go:266-271` — `core[ClientAddr] = req.RemoteAddr` and `core[ClientHost]` (overridden by
  XFF when present) are **string copies taken at entry**, before router middlewares.
- `logger.go:379` — `redactHeaders(logDataTable.Request.headers, fields, "request_")` runs at
  **log-write time**, after the entire chain.

⇒ `ClientAddr` / `ClientHost` cannot be influenced by any plugin. But **request header fields in
the access log reflect middleware mutations**, so a header the normalizer sets *is* loggable.
Field naming is `request_<Canonical-Header-Key>`; `logger.go:142` canonicalizes configured names.

### F11 (new, measured) — Bunny overwrites client-supplied identity headers

Method: Bunny Edge Script echo app returning received headers, behind a disposable Pull Zone.

- With no Edge Rules, the origin receives `X-Real-IP: <real client>` **and**
  `X-Forwarded-For: <real client>` — XFF contains the client only, **not** `CDN-IP, user-IP`.
- Client-supplied `X-Real-IP: 9.9.9.9` / `X-Forwarded-For: 8.8.8.8`, including **duplicate**
  `X-Real-IP` headers, were all overwritten. The origin still saw the real client IP.

⇒ Ordinary internet clients cannot spoof identity through Bunny. This eliminates what was the
largest unresolved risk in this design.

### F12 (new, measured) — Bunny's `CDN-*` namespace is protected from Pull Zone owners

- Edge Rules refuse to set `CDN-PullZoneId`: *"Header names starting with CDN- are not allowed"*.
- Edge Scripting middleware could rewrite `X-Real-IP` / `X-Forwarded-For`, but the origin still
  received genuine Bunny-generated `CDN-*` metadata.

⇒ Within Bunny, `CDN-*` is a meaningfully stronger channel than ordinary forwarding headers.
Note it is *only* stronger inside Bunny: `CDN-*` is not in Traefik's `XHeadersSet`, so a **direct**
client can send whatever `CDN-*` headers it likes. `CDN-*` metadata is only *provider-authenticated*
when the request has actually traversed Bunny — which is why the Bunny preset documentation
recommends combining a `CDN-*` predicate with Bunny peer-range trust. That is deployment guidance,
not a validation rule (§4.1). (The plugin does not strip these headers — see §6.3.)

### F13 (new, measured) — `CDN-Host` tracks the hostname Bunny actually routed

Same Pull Zone reached via three hostnames returned `CDN-Host: test-pabb4.b-cdn.net`,
`test-pabb4.bunny.run`, `btest.oandc.fun` respectively. Sending
`Host: definitely-not-your-domain.example` was rejected by Bunny itself ("Domain suspended or not
configured") and never reached the origin.

⇒ `CDN-Host` is a hostname Bunny accepted and routed, not a protected copy of arbitrary client
input. See F16 for what this does **not** prove about ownership.

### F14 (new) — CrowdSec's Traefik **log parser** derives `source_ip` from `ClientHost`

`parsers/s01-parse/crowdsecurity/traefik-logs.yaml`:
```yaml
- parsed: remote_addr
  expression: "TrimSpace(Split(evt.Unmarshaled.traefik.ClientHost, ',')[-1])"
...
- meta: source_ip
  expression: "evt.Parsed.remote_addr"
```
`source_ip` is the **rightmost** comma-separated element of `ClientHost` — which per F10 is
frozen pre-middleware. The same file already reads `evt.Unmarshaled.traefik["request_User-Agent"]`,
confirming the `request_<Header>` field naming used by the §8 fix.

### F15 (new, verified) — `:0` is a safe synthetic port

Every consumer found uses `net.SplitHostPort` and then discards or string-handles the port:
Traefik `pkg/ip/strategy.go:28` (`RemoteAddrStrategy`), accesslog `silentSplitHostPort`
(`logger.go:475`), proxy XFF append (`proxy.go:71`), CrowdSec `ip.go:124`, Badger `main.go:508`,
mtlswhitelist `twofactor.go:128` / `webpages.go:123`. None parses the port numerically or
range-checks it. Confirmed by execution: `net.SplitHostPort` accepts `1.2.3.4:0` and
`[2001:db8::1]:0`; `net.JoinHostPort` brackets IPv6 correctly.

### F16 (new, measured) — Bunny attaches custom hostnames **without DNS verification**

A hostname the operator does not own (`testmyshitnig.com`) was added to the disposable Pull Zone
and immediately routed:
```
curl -H 'Host: testmyshitnig.com' https://test-pabb4.b-cdn.net/
  -> cdn-host: testmyshitnig.com   (and origin Host: testmyshitnig.com)
```
Bunny performed no CNAME or ownership check. `CDN-Host` therefore reflects a hostname merely
**registered on the zone**, not one the zone owner controls.

⇒ **`hostSuffixes` is not ownership proof.** An attacker creates their own Pull Zone, registers
`anything.lochnair.net` on it (any label we have not already taken), points the origin at our IP,
and produces a `CDN-Host` that satisfies `*.lochnair.net`. It must therefore never be described as
authentication. It is retained in §4.2 as optional weak defence in depth — it still raises effort
and filters misconfiguration at near-zero operational cost — but it is neither a default nor a
security boundary.

What survives is narrower, and one part of it has since been **measured**: attempting to attach an
already-registered exact hostname to a second Pull Zone is **rejected as already registered**. So
hostname → Pull Zone is globally unique, and a hostname we have already registered cannot be
claimed by another account. Any *unregistered* name in our namespace remains freely claimable.

⇒ `hostExact` over hostnames we actually serve rests on provider-enforced uniqueness and is sound,
subject to one remaining untested property (§9.4): that `CDN-Host` reflects the **routed** hostname
and is not affected by a zone's origin-Host override. `hostSuffixes` is restored in §4.2 but
explicitly as *weak defence in depth*, never as ownership proof.

### F17 (new, observed) — Bunny does not produce a clean `X-Forwarded-Proto`

The same capture returned `x-forwarded-proto: "https, https"` although the client sent none. The
zone had Edge Rules and Edge Scripting active, so the exact cause is unclear, but the conservative
conclusion is independent of the cause: **the inbound `X-Forwarded-Proto` may arrive comma-joined
and must not be trusted verbatim.** Under posture B, Traefik's `rewrite()` only sets the header when
it is empty, so a comma-joined value would pass straight through to the backend. §6.4's
delete-and-re-derive rule already covers this; F17 is the evidence that it is load-bearing rather
than theoretical.

Also visible and worth recording: Bunny emits `CDN-ConnectionId`, `CDN-RequestId`, `CDN-JA4`
(client TLS fingerprint), `CDN-LoopCount`, `CDN-ProxyVer`, `CDN-MobileDevice`, `CDN-ServerZone`,
`CDN-RequestStateCode` alongside the already-known `CDN-Host` / `CDN-PullZoneId` /
`CDN-RequestCountryCode` / `CDN-ServerId`. All are in the protected namespace (F12). None carries
client IP; none is used by this design.

### F18 (new, investigated) — unmatched requests are logged, and are distinguishable from rejections

Investigated because a blanket "drop every event lacking `request_X-Real-Ip`" would have discarded
scanner and probe traffic that never matched a router — exactly what CrowdSec should be detecting.

- **Unmatched requests are logged.** `pkg/server/router/router.go:212` and `:234` build
  `observabilityMgr.BuildEPChain(...).Then(http.NotFoundHandler())` and install it via
  `muxer.SetDefaultHandler(...)`. The observability chain contains the access logger, so a request
  matching no router still produces a log line (status 404).
- **The entrypoint-default normalizer does not run for them.** Entrypoint default middlewares are
  attached to *routers* through the `@internal` model (F2). No router, no middleware chain.
- **`RouterName` is set outside the middleware chain.** `router.go:371-373` appends
  `accesslog.NewConcatFieldHandler(next, accesslog.RouterName, routerName)` *before*
  `chain.Extend(*mHandler)`, so it is populated for any request a router matched — **including one
  the normalizer subsequently rejected**. On the unmatched path it is never set, and since
  `logger.go:373` iterates over the populated `Core` map, the field is **omitted from the JSON
  entirely** rather than emitted empty.
- **`ClientAddr` is socket-backed and unspoofable.** `logger.go:266` — `core[ClientAddr] =
  req.RemoteAddr`, taken at entry. Unlike `ClientHost` (`logger.go:269`, overridden by XFF when
  present, so client-controllable under posture B) it never derives from a header.

⇒ Three states are cleanly distinguishable in the access log:

| | `RouterName` | `request_X-Real-Ip` | Meaning | `source_ip` |
|---|---|---|---|---|
| A | present | present | normalized | the header (authoritative) |
| B | **absent** | absent | no router matched | host of `ClientAddr` (socket peer) |
| C | present | **absent** | router matched, normalizer rejected or did not run | **none — drop** |

Caveat for B: a probe arriving *through* a CDN at a hostname with no router is attributed to the POP
address, since nothing normalized it. That is what the optional CDN-range detection whitelist in
§8.2 covers.

Incidental defect to avoid inheriting: the stock parser derives its `dest_addr` via
`Split(ClientAddr, ':')[0]`, which is wrong for IPv6 (`[2001:db8::1]:443` → `[2001`). Any expression
we write over `ClientAddr` must handle bracketed IPv6.

---

## 2. Posture decision

F1 still means Bunny's identity cannot survive to the plugin under a stock entrypoint.

**Posture A** — keep `forwardedHeaders` secure; move identity into a non-Traefik-managed header
via a per-Pull-Zone Edge Rule (Cloudflare needs nothing; `CF-Connecting-IP` already survives).
Smallest plugin. Forgetting a zone fails **closed** (peer in feed, identity header missing → 403),
not open.

**Posture B** — `forwardedHeaders.insecure: true`; the plugin owns all forwarded-header hygiene.
Works with Bunny's stock `X-Real-IP`. **No per-Pull-Zone configuration.**

**Posture C** — static `forwardedHeaders.trustedIPs`. Still rejected: static config, restart to
update, reintroduces the external range plumbing this project exists to remove.

### Recommendation: posture B, conditional on the §8 access-log fix

An earlier draft of this design hedged toward posture A on security grounds. Two measured facts
settle it the other way:

1. **F11 removes A's main security advantage.** The worry was that a client might smuggle
   identity through Bunny. Measured: it cannot. The Edge Rule bought protection against a threat
   that does not exist.
2. **F14 + F10 show the real risk of B is in the log path, and it is fixable.** With
   `insecure: true`, inbound XFF survives to the access logger, so `ClientHost` — and therefore
   CrowdSec's `source_ip` — becomes client-controllable on *direct* traffic. That is a remote,
   unauthenticated ability to get an arbitrary third party banned, since the resulting decision is
   enforced by the bouncer against the real owner of that IP. **This is worse than anything in
   the pre-measurement threat model and must be fixed, not accepted.** §8 fixes it.

Note posture A is *also* broken on the log path, differently and by default: with a secure
entrypoint Traefik deletes XFF, so `ClientHost` is the socket peer and CrowdSec detection
attributes all CDN traffic to **POP addresses**, eventually banning a POP and blackholing all
Bunny traffic. The §8 fix is required either way; it is not a tax specific to posture B.

What posture B costs: the plugin must delete and re-assert
`X-Forwarded-Proto` / `-Scheme` / `X-Scheme`, `-Host`, `-Port`, `-Prefix`, `-Uri`, `-Method`,
`-Server`, and unconditionally delete `X-Forwarded-Tls-Client-Cert{,-Info}`. Safe only because of
F2. Build the posture as a config flag so A remains available without a code change.

Rejected variant: a dedicated CDN entrypoint on another port. It is still per-zone configuration
(the origin URL), and forgetting it fails **open** — the request lands on :443 and the POP becomes
the client. Strictly worse than A's Edge Rule.

---

## 3. Architecture and request flow

The empirical results support this shape. Source = `{ name, trust, extract }`,
evaluated as an ordered list, first trust match wins.

1. `peer` := socket peer from `req.RemoteAddr`. **Never** from a header.
2. Walk `sources` in order; first source whose `trust` predicates **all** hold for this request wins.
3. Matched → apply `extract` → `client`, or a fail-closed action.
4. No match → `client = peer` (direct; first-class, including all mTLS routes).
5. Sanitize headers, set `X-Real-Ip`, rewrite `RemoteAddr`, call `next`.

```
socket peer ─┬─ matches a source? ──no──> client = peer          (direct / mTLS)
             └─ yes ─> extract identity ─┬─ valid ──> client = extracted
                                         └─ invalid ─> 403 (fail closed)
                                    ↓
              sanitize identity headers (both paths)
              set X-Real-Ip = client        ← also the access-log/CrowdSec channel (§8)
              set RemoteAddr = client:0     (normalized) / unchanged (direct)
                                    ↓
                      CrowdSec → Badger → backend
```

Still **no XFF-chain walking in v1**. Bunny and Cloudflare both provide clean single-value
headers; a chain walker serves no current provider and is where spoofing bugs live.

---

## 4. Configuration shape

```yaml
http:
  middlewares:
    realclient:
      plugin:
        realclient:
          entrypointForwardedHeaders: insecure   # insecure | secure  (posture B | A)

          sources:                                # ordered; first full match wins
            - name: bunny
              preset: bunny
              # optional hardening, all off by default — see §4.2:
              #   trust: { hostSuffixes: {header: Cdn-Host, suffixes: ["lochnair.net"]} }
              #   trust: { hostExact: {header: Cdn-Host, values: [...]} }
              #   trust: { headerEquals: {name: X-Origin-Auth, valueFrom: "file:/run/secrets/bunny"} }
            - name: cloudflare
              preset: cloudflare
            - name: internal-lb
              trust: { static: ["10.42.0.0/16"] }
              extract: { header: X-Real-Ip, mode: single }

          onTrustedButInvalid: reject             # reject | direct  (default reject)
          rejectStatusCode: 403
          allowPrivateClient: false
          setRealIP: true
          feedCacheDir: /var/lib/traefik/clientip
```

Presets are **pure data** — a `map[string]Source` literal expanded before request handling, every
field overridable inline. If a provider cannot be expressed as a preset, extend the generic
config; never add a provider-specific request path.

```yaml
# preset: bunny
trust:
  feeds:
    - { url: "https://api.bunny.net/system/edgeserverlist/plain", format: lines,      minEntries: 100 }
    - { url: "https://api.bunny.net/system/edgeserverlist/ipv6",  format: json-array, minEntries: 50  }
  refreshInterval: 30m
extract: { header: X-Real-Ip, mode: single }

# preset: cloudflare
trust:
  feeds:
    - { url: "https://www.cloudflare.com/ips-v4", format: lines, minEntries: 10 }
    - { url: "https://www.cloudflare.com/ips-v6", format: lines, minEntries: 5  }
  refreshInterval: 12h
extract: { header: Cf-Connecting-Ip, mode: single }
```

### 4.1 Trust model

A source's `trust` is a small fixed set of predicates in two families, deliberately **not** a
boolean-expression DSL.

```
# peer-address family — jointly ONE predicate
  static:        [CIDR|IP, ...]        # literal list
  feeds:         [FeedSpec, ...]       # dynamically refreshed sets

# header family — each an independent predicate
  headerEquals:  {name, valueFrom}     # header == secret, constant-time
  headerIn:      {name, values}        # header ∈ exact set, byte-compare
  hostExact:     {header, values}      # header ∈ set, DNS-host normalized
  hostSuffixes:  {header, suffixes}    # header ∈ domain namespace, DNS-label semantics (WEAK)
```

Each predicate is independently sufficient; none is privileged. What differs is what each one
*proves* and what it assumes about the path the request took:

| Predicate | What it proves | Provenance assumption | Phase |
|---|---|---|---|
| `static` | peer address ∈ literal list | Socket peer — unforgeable at the plugin. | v1 |
| `feeds` | peer address ∈ refreshed set | Socket peer — unforgeable; trust in the feed publisher (§9.5). | v1 |
| `headerIn` | header ∈ exact set | Header is only authoritative if something upstream guarantees it. | v1 |
| `hostExact` | host header ∈ set (DNS-normalized) | Same. For `CDN-Host`, provider-authenticated **only if the request traversed Bunny**. | v1 |
| `hostSuffixes` | host header ∈ domain namespace | Same, and weaker still — not ownership proof (§4.2). | v1 |
| `headerEquals` | header == shared secret | Anyone holding the secret; unforgeable without it, on any path. | v1.1 |

**The plugin does not police these combinations.** It cannot know a deployment's surrounding trust
guarantees: a header that is trivially forgeable on the public Internet may be entirely authoritative
behind another authenticated proxy, a private network, or a provider that overwrites it. So
`hostSuffixes` alone, or `headerIn` alone, are legal configurations, and the documentation's job is
to explain provenance rather than to forbid.

The one place this gets concrete guidance is the Bunny preset: **`CDN-*` metadata is only
provider-authenticated when the request has actually traversed Bunny** (F12), so a `CDN-Host` or
`CDN-PullZoneId` predicate should be combined with Bunny peer-range trust there. That is deployment
guidance in the preset docs, not a generic validation rule.

**Composition rules — the whole model:**

1. `static` and `feeds`, when both present, are **unioned** into a single peer-address predicate.
   They answer one question ("is this peer the provider?") from two data sources.
2. Every predicate that is configured must hold. Plain AND.
3. **At least one predicate is required.** A source with an empty `trust` is a config error.
4. There is no `or`, no nesting, no expression language. If a deployment needs alternatives, it
   writes two sources — the ordered list already provides that, with first-match semantics.

**No anchor of any kind is required.** Any single predicate may stand alone — `feeds` only, `static`
only, `headerEquals` only, `headerIn` only, `hostExact` only, `hostSuffixes` only — or any ANDed
combination. An authenticated header as the sole mechanism is the right model for an upstream with
no stable address range (`headerEquals` lands in v1.1):

```yaml
- name: authenticated-upstream
  trust:
    headerEquals: { name: X-Origin-Auth, valueFrom: "file:/run/secrets/upstream_auth" }
  extract: { header: X-Real-Ip, mode: single }
```

and compositions work the obvious way:

```yaml
- name: bunny-hardened
  preset: bunny                                   # supplies trust.feeds + extract
  trust:
    headerEquals: { name: X-Origin-Auth, valueFrom: "file:/run/secrets/bunny" }
```
which is `feeds AND headerEquals`.

### 4.1.1 Header predicates vs host predicates

`headerEquals` / `headerIn` operate on **raw header bytes**. `hostExact` / `hostSuffixes` apply
**DNS-host normalization** first: lowercase, strip a trailing dot, strip any port, reject empty or
non-hostname values.

These are separate families on purpose. `CDN-PullZoneId` is an opaque numeric identifier and must
**not** be run through hostname normalization merely because `CDN-Host` is — a Pull Zone ID has no
labels, no trailing dot and no port, and treating it as a hostname would be a category error that
invites surprising matches. Use:

```yaml
trust: { headerIn:   { name: Cdn-Pullzoneid, values: ["6498612"] } }   # opaque identifier
trust: { hostExact:  { header: Cdn-Host,     values: ["btest.oandc.fun"] } }  # hostname
```

`headerIn` is the generic primitive; `hostExact` is the hostname-aware specialization. Neither is
recommended as a default (§4.2).

### 4.2 Host predicates: a spectrum, not a binary

All of these are optional ANDed predicates over a **protected** provider header. None is enabled by
default; the default posture is `feeds` only. They differ in what they actually prove:

```
range only
    provider-level trust
    "this came from Bunny infrastructure"

range + host suffix
    cheap, weak defence in depth
    NOT proof of account or domain ownership

range + exact protected hostname, or Pull Zone ID
    stronger, provider-enforced binding
    per-resource maintenance

range + shared secret (headerEquals)
    explicit account binding
    per-zone setup
```

**`hostSuffixes` — weak defence in depth, with an honest label.** An earlier draft removed this
outright after F16 showed Bunny performs no DNS-ownership check. That conclusion was too absolute.
It is true that a determined Bunny customer can register some unused label under `lochnair.net` on
their own zone and defeat the predicate, so it is **not** authentication and must never be
described as such. But it costs essentially nothing when many zones already share a few domain
families, it raises required effort, and it filters unrelated Bunny traffic and misconfiguration —
including our own zones accidentally pointed at the wrong origin. For a homelab that is a
reasonable trade. Implement it; document it as weak.

Matching must use DNS-label semantics, never `strings.HasSuffix`:
```
match(host, suffix) := lower(host) == lower(suffix)
                    || strings.HasSuffix(lower(host), "." + lower(suffix))
```
Normalize first: lowercase, strip a trailing dot, strip any port, reject empty or non-hostname
values. `evil-lochnair.net` must not match `lochnair.net`.

Config validation must **reject** `b-cdn.net` and `bunny.run` as suffixes. Every Bunny customer's
zone ends with those, so accepting them would manufacture a false sense of protection.

**`hostExact` — provider-enforced binding.** Now supported by measurement (F16): hostname → Pull
Zone is globally unique, and re-registering an in-use hostname on a second zone is rejected. So an
attacker cannot claim a hostname we already serve.

```yaml
trust: { hostExact: { header: Cdn-Host,       values: ["btest.oandc.fun", "www.example.net"] } }
trust: { headerIn:  { name:   Cdn-Pullzoneid, values: ["6498612"] } }
```
Note the Pull Zone ID uses `headerIn`, not `hostExact` — see §4.1.1.

One property remains untested (§9.4): whether `CDN-Host` follows the *routed* hostname or a zone's
origin-Host override. It matters because an attacker does not need a matching hostname to reach the
right router — they can override the origin `Host`. If `CDN-Host` is computed from the received
hostname (which F12's protection of `CDN-*` and all observed behaviour suggest), the predicate
holds; if it follows the override, only the Pull Zone ID form retains value.

Neither `hostExact` nor the `headerIn` Pull Zone ID form is recommended as a default: keeping
per-host or per-zone allowlists
synchronized by hand works directly against the low-maintenance goal that motivates this project.
Forgetting an entry fails **closed** (403), so the failure is loud rather than silent — which makes
it a defensible opt-in, not a default.

`*.b-cdn.net` / `*.bunny.run` names are globally unique, so *exact* matching on them is sound, but
it is per-zone maintenance with no advantage over the Pull Zone ID. They are never a namespace.

---

## 5. Range-feed subsystem (trimmed for v1)

```go
var registry = struct {
    mu    sync.Mutex
    feeds map[string]*feed   // key: url + "|" + format
}{feeds: map[string]*feed{}}

type feed struct {
    spec    FeedSpec
    current atomic.Value // *rangeSet (immutable)
    etag    atomic.Value // string
}

type rangeSet struct {
    exact    map[netip.Addr]struct{}
    prefixes []netip.Prefix
    loadedAt time.Time
}
```

**Kept in v1** — the properties that make it reliable:
- Never fetch per request; reader path is one `atomic.Value.Load()`.
- **Dedupe, don't refcount.** `New()` re-runs on every reload and there is no shutdown hook (F8).
  Key by URL, start at most one updater per URL, let it live for the process.
- Build the whole new set, then `Store` — atomic publication, no partial visibility.
- **Last-known-good on any failure**: keep the previous set, log, retry.
- Strict parsing: HTTP 200 required, body size cap, and **every entry must parse or the whole
  payload is rejected**.
- Catastrophic-corruption guards, as fixed constants rather than knobs: reject `0.0.0.0/0` and
  `::/0`; reject private / loopback / link-local / unspecified entries; reject prefixes shorter
  than `/8` (v4) or `/19` (v6). Cloudflare's shortest are `/13` and `/29`, so there is ample margin.
- `minEntries` per feed (a preset field, not a user-facing knob).
- ETag conditional GET — Bunny serves one, which makes refresh nearly free.
- Fixed `refreshInterval` with ±10% jitter, plus a single `retryInterval` constant (2 min) used
  after a failed attempt. No backoff curve.
- Explicit `http.Client{Timeout: 15s}`.
- **Independence**: one goroutine and one `atomic.Value` per feed. A source's set is the union of
  its feeds'; one broken feed leaves the other's LKG usable; one broken source never affects
  another.

**Cold start, two layers:**
1. Read the disk cache synchronously — local, instant.
2. If absent, perform **one** bounded synchronous fetch (5s budget) before returning from `New()`.
   Only ever happens once per URL per process, because of the registry.
3. Otherwise: empty set, ERROR on every refresh attempt until first success.

A third layer — a bundled compiled-in snapshot — was considered and dropped. Disk cache earns its place — a homelab
Traefik restarting before the WAN is up is a realistic scenario, and an empty Bunny set means POP
addresses get treated as clients. Note the §8 CrowdSec whitelist independently covers that window.

**Deferred out of v1**: shrink-percentage heuristics, configurable prefix floors, exponential
backoff, and general feed-policy knobs. The point is a reliable normalizer, not a service-discovery
framework inside Yaegi.

---

## 6. Normalization and header sanitization

Read before deleting:

1. Read `peer` from `req.RemoteAddr`.
2. Evaluate trust predicates and `extract` (reads identity, host and secret headers).
3. Delete all identity headers, *including the ones just read*.
4. `req.Header.Set("X-Real-Ip", client)` — required by F7, and the access-log channel in §8.
5. Rewrite `RemoteAddr` (below).

Always `netip.ParseAddr` → `.Unmap()` (so `::ffff:1.2.3.4` cannot evade a ban on `1.2.3.4`) →
strip IPv6 zone → re-`String()`. Never propagate an unvalidated string.

### 6.1 `RemoteAddr` port

**The invariant is only that `RemoteAddr` remains valid `host:port`** (F4 — CrowdSec bans every
request if `SplitHostPort` fails). The port value itself carries no meaning for any consumer
inspected (F15): all of them split and discard it.

- **Normalized requests**: `net.JoinHostPort(client, "0")` → `1.2.3.4:0`, `[2001:db8::1]:0`.
  Preferred, because retaining the CDN peer's ephemeral port yields a hybrid tuple of real client
  IP + POP source port — the same hybrid identity the HAProxy design deliberately avoided. `:0` is
  honest: there is no known client port.
- **Direct requests**: leave `req.RemoteAddr` untouched.

This is a cleanliness choice, **not a required invariant**. Preserving the observed peer port would
work equally well and is a legitimate implementation decision.

### 6.2 Delete list (both paths, direct and proxied)

`Forwarded`, `X-Forwarded-For`, `X-Real-Ip`, `X-Client-Ip`, `X-Cluster-Client-Ip`,
`X-Original-Forwarded-For`, `X-Originating-Ip`, `True-Client-Ip`, `Cf-Connecting-Ip`,
`Cf-Connecting-Ipv6`, `Cf-Pseudo-Ipv4`, `Cf-Visitor`, `Cf-Ipcountry`, `Fastly-Client-Ip`,
`Fly-Client-Ip`, `X-Azure-Clientip`, `X-Azure-Socketip`, `X-Appengine-User-Ip`, plus every
configured `extract.header` across all sources.

**Deletion is decided by the header's *role*, not by the fact that the plugin read it.** Three roles,
three rules:

| Role | Predicate / source | Action |
|---|---|---|
| Client identity | `extract.header`, plus the fixed list above | **Removed**, then a single canonical `X-Real-Ip` is set. Required to establish one effective client identity. |
| Authentication secret | `trust.headerEquals.name` | **Stripped after use.** It is a credential; no backend has any business seeing it. |
| Provider metadata used for matching | `trust.headerIn.name`, `trust.hostExact.header`, `trust.hostSuffixes.header` (e.g. `CDN-Host`, `CDN-PullZoneId`) | **Left untouched.** Inspecting a header is not a reason to delete it (§6.3). |

Sweep `_`-variants the way Traefik's `isManagedXHeader` does — Go's server preserves `X_Real_IP`
as a distinct map key.

### 6.3 Scope limit: what this plugin does *not* touch

**Mutation principle.** The plugin only removes or rewrites a header where doing so is required to
(a) establish one consistent effective client identity, or (b) reconstruct Traefik-managed
forwarding state that posture B leaves client-controllable (§6.4). Nothing else.

This is not a generic header-security layer. An earlier rule requiring `CDN-*` metadata to be
stripped on the direct path is **withdrawn**. Those headers already reach backends today under stock Traefik;
removing them would change unrelated downstream-visible metadata for no benefit to the project's
goal, and would make the plugin's blast radius larger than its purpose.

The plugin **reads** provider metadata (`CDN-Host`, `CDN-PullZoneId`, …) when a configured trust
predicate requires it, and otherwise leaves it entirely alone — on every path, trusted or direct.

Consequence worth stating plainly, unchanged by this decision: because `CDN-*` is not in Traefik's
`XHeadersSet`, a direct client can send arbitrary `CDN-*` headers. That is true today with or
without this plugin, and a backend that trusts `CDN-RequestCountryCode` from an unauthenticated peer
is making its own mistake — not one this plugin should silently paper over.

**Deployment guidance, not a validation rule.** On *public* ingress, `CDN-*` is
provider-authenticated only once provider provenance has been established, so the sensible and
default Bunny posture combines a `CDN-Host` or `CDN-PullZoneId` predicate with Bunny peer-range
trust. That guidance belongs in the Bunny preset documentation. The generic plugin still allows
`headerIn`, `hostExact`, `hostSuffixes` and the rest to stand alone, because a deployment may have
its own guarantees — a private network, or an authenticated proxy in front — that make such a header
authoritative. See §4.1 for the per-predicate provenance table. No validation restriction is
imposed.

### 6.4 Additional hygiene under `entrypointForwardedHeaders: insecure`

Delete and re-assert, mirroring Traefik's `rewrite()`: `X-Forwarded-Proto` / `-Scheme` /
`X-Scheme` (from `req.TLS`, with `ws`/`wss` for upgrades), `X-Forwarded-Host` (from `req.Host`),
`X-Forwarded-Port`, `X-Forwarded-Prefix`, `-Uri`, `-Method`, `-Server`. Unconditionally delete
**`X-Forwarded-Tls-Client-Cert` and `X-Forwarded-Tls-Client-Cert-Info`** — otherwise a client
forges certificate identity for any downstream `passTLSClientCert` consumer.

Not deleted on the trusted path: `Via`, `CDN-ServerId`, `CDN-RequestCountryCode` — metadata, useful
for diagnostics.

---

## 7. Fail-closed semantics

| Situation | Action |
|---|---|
| No source matches `peer` | direct; `client = peer`; `RemoteAddr` untouched |
| Source matched; identity header absent | **403** (`onTrustedButInvalid`, default `reject`) |
| Header unparseable, empty, or whitespace | **403** |
| Header present more than once (`len(Header.Values(h)) > 1`) | **403** — `Get` returns only the first; classic bypass. (Bunny collapses duplicates per F11, so this can only indicate a non-Bunny path.) |
| Comma / multiple values in `mode: single` | **403** |
| Extracted address is private / loopback / unspecified | **403** unless `allowPrivateClient` |
| The peer-address predicate matches but another configured predicate (`hostSuffixes`, `hostExact`, `headerIn`, `headerEquals`) fails | **403** — "known CDN, failed additional check" is a conflict. Falling through to direct would make the POP the client and get it banned. |
| Peer matches no range at all, wrong/absent secret | direct — nothing suspicious was established |
| Feed never loaded (cold start) | source cannot match → treated as direct; ERROR on every refresh until first success; window mitigated by disk cache and by the §8 whitelist |
| Rejection response | bare status, empty body, no echo of input; `next` **not** called; **all identity headers deleted and `X-Real-Ip` left unset** (see §8.2: an unset canonical header is what makes the log path drop the event instead of attributing it to a POP). Attribution lives in the plugin's own structured log line. |

Never emit a `RemoteAddr` the plugin did not validate. On internal error, prefer 403 over guessing.

---

## 8. CrowdSec: two independent IP paths

A naive reading — "CrowdSec needs zero configuration" — is correct **only** for the request-time
path. It misses that this deployment also feeds Traefik access logs to CrowdSec via the
`crowdsecurity/traefik` collection, which resolves identity by a completely different route.

### 8.1 The two paths

| | Remediation (bouncer + AppSec) | Detection (log acquisition → scenarios) |
|---|---|---|
| Mechanism | HTTP middleware, request-time | Traefik access log → `crowdsecurity/traefik-logs` parser |
| IP source | `RemoteAddr` once inbound XFF is deleted (F5) | `source_ip` = rightmost element of `ClientHost` (F14) |
| Sees plugin output? | **Yes** | **No** — `ClientHost` is frozen at entry (F10) |
| Status | Correct, zero config | **Wrong under both postures** |

Under posture A: XFF deleted at entry → `ClientHost` = socket peer → CrowdSec detection attributes
all CDN traffic to POP addresses and eventually bans a POP, blackholing Bunny.
Under posture B: XFF survives → correct for Bunny traffic, but **client-controllable on direct
traffic** → an unauthenticated remote party can cause an arbitrary third-party IP to be banned, and
that ban *is* enforced by the bouncer against the real owner.

Both are unacceptable. The fix is required regardless of posture.

### 8.2 Recommended fix — log the normalized header, teach the parser to use it

Viable because of F10: `Request.headers` is a live reference serialized after the chain, so a
header the plugin sets appears in the log. F14 confirms the field naming (`request_User-Agent` is
already consumed by the stock parser).

**Traefik** (static config):
```yaml
accessLog:
  format: json
  fields:
    headers:
      names:
        X-Real-Ip: keep
```

**CrowdSec** — a small parser at `s02-enrich`, after the stock Traefik parser, overriding
`source_ip` from the canonical header:
```yaml
onsuccess: next_stage
filter: "evt.Parsed.program startsWith 'traefik' && evt.Unmarshaled.traefik['request_X-Real-Ip'] != nil"
statics:
  - meta: source_ip
    expression: "evt.Unmarshaled.traefik['request_X-Real-Ip']"
```

**It must never fall back to `ClientHost`.** `ClientHost` is frozen pre-middleware (F10) and is
either the CDN POP address or a client-forged XFF value — both would let a request that *failed*
normalization create a decision against the wrong party.

But a blanket drop of everything lacking the canonical header would be wrong too: it would discard
scanner and probe traffic that never matched a router, which is precisely what the detection path
exists to catch. F18 establishes that the two cases are distinguishable, so the rule is three-way:

| `RouterName` | `request_X-Real-Ip` | Meaning | Action |
|---|---|---|---|
| present | present | normalized | `source_ip` = the header |
| **absent** | absent | no router matched (404 probe) | `source_ip` = host of `ClientAddr` — socket-backed, unspoofable |
| present | **absent** | normalizer rejected, or did not run | **drop; no decision** |

The second row is what keeps probe detection working. The third is what makes §7's rejection rule
(delete identity headers, leave `X-Real-Ip` unset) effective: a plugin-rejected request produces no
canonical header *and* has a `RouterName`, so it is dropped rather than attributed to a POP.
Attribution for those events lives in the plugin's own structured log.

Sketch of the drop rule, to be written as a whitelist or an `evt.Whitelisted` static:

```yaml
name: local/traefik-unnormalized
description: "Drop Traefik events that matched a router but were not normalized"
filter: >
  evt.Parsed.program startsWith 'traefik'
  && evt.Unmarshaled.traefik.RouterName != nil
  && evt.Unmarshaled.traefik['request_X-Real-Ip'] == nil
whitelist:
  reason: "matched a router but normalization did not complete; ClientHost is untrustworthy"
  expression: ["true"]
```

and the unmatched-request enrichment must extract the host from `ClientAddr` **handling bracketed
IPv6** — the stock parser's `Split(ClientAddr, ':')[0]` is wrong there (F18).

One consequence worth accepting knowingly: a child router (`ParentRefs != nil`, §11) receives no
entrypoint-default middleware, so its events land in row three and are dropped. That is a detection
gap, not a security hole, and it is one more reason to confirm Pangolin emits none.

*The exact CrowdSec YAML above is illustrative and should be validated against a running instance
during implementation; the requirement it encodes is not negotiable.*

Together this works identically under postures A and B, and neutralizes direct-path XFF spoofing
because the value comes from the plugin, not from client input.

**Optionally, also whitelist the CDN ranges as `source_ip`.** Post-fix the only remaining way a POP
address becomes `source_ip` is the cold-start window before a feed has loaded, where CDN traffic is
treated as direct. A coarse, possibly-stale static list is fine for this — it is a safety net
against banning our own CDN, not a trust decision.

### 8.3 Alternatives considered

- **Drop log acquisition entirely.** Cheapest, but loses real detection value — 4xx bruteforce,
  path probing, bad-UA scenarios are what the collection provides; the bouncer only enforces. Not
  recommended, though it is a legitimate fallback if the custom parser proves fragile across
  CrowdSec upgrades.
- **Point CrowdSec at backend logs.** Backends see a correct XFF (F3), but they are heterogeneous
  and this multiplies parser work. Rejected.
- **Fix `ClientHost` from the plugin.** Impossible — frozen at entry (F10).
- **Conclude posture B is unattractive.** Rejected: posture A's log path is broken *by default* and
  in a more dangerous direction (POP bans). The fix is orthogonal to the posture choice.

The residual cost is one CrowdSec parser file and one access-log field — a per-deployment step, but
a single one, not per-Pull-Zone.

### 8.4 Remaining CrowdSec config after adoption

Bouncer: **unchanged.** Leave `forwardedHeadersTrustedIps: []` and `clientTrustedIps: []` at
defaults. Explicitly do not put CDN ranges in `forwardedHeadersTrustedIps` — different concept, and
inert once XFF is deleted.

Badger: `disableDefaultCFIPs: true`, `trustip: []`, `customIPHeader: ""` → straight to the
`RemoteAddr` fallback. Works without these because `CF-Connecting-IP` is deleted, but they remove
the F6 WARP hazard outright.

mtlswhitelist: unchanged, and only because `setRealIP: true` (F7). Dedicated regression test.

Ordering guaranteed by F2, not by Middleware Manager discipline.

---

## 9. Threat model

1. **Spoofed identity headers from a direct client** — mitigated: trust derives only from the
   socket peer; identity headers deleted unconditionally on both paths. Note `CDN-*` metadata is
   deliberately *not* touched (§6.3) — it is settable by a direct client today regardless, which is
   why the Bunny preset documentation pairs `CDN-*` predicates with peer-range trust (§4.1).
2. **Spoofed identity *through* Bunny by an ordinary client** — **eliminated, measured** (F11).
   Bunny overwrites `X-Real-IP` and `X-Forwarded-For`, including duplicates. This was the largest
   open risk before measurement.
3. **Third-party ban injection via the log path** — the most serious issue found in this revision.
   Fixed by §8.2. Would otherwise let any unauthenticated client get arbitrary IPs banned.
4. **Another Bunny customer fronting our origin** — a **residual** risk of feed-only trust, and
   explicitly *not* a design driver. The project exists to solve dynamic upstream trust; perfect
   provider-account authentication is a separate, optional concern that must not be allowed to
   dominate v1 complexity. Feed-only is the accepted baseline for this deployment.
   A range feed proves *"came from Bunny infrastructure"*, not *"came through one of my zones"*.
   Measured (§2 of the brief): a Pull Zone owner can forge `X-Real-IP` and `X-Forwarded-For` via
   Edge Rules or Edge Scripting middleware. So another customer could point a zone at the origin
   and forge client IPs, defeating CrowdSec bans.
   - Accepted for a personal/homelab deployment, per instruction. It also applies unchanged to the
     existing HAProxy arrangement, so it is not a regression.
   - Mitigations, in ascending strength and cost (full discussion in §4.2):
     - `hostSuffixes` on `CDN-Host` — **weak defence in depth**, not ownership proof. F16 showed
       Bunny requires no DNS verification to register a hostname, so an attacker can register an
       unused label under our domain. Still raises effort and filters misconfiguration at
       essentially zero operational cost. Retained with that label.
     - `hostExact` on `CDN-Host` over hostnames we already serve — provider-enforced, since
       hostname → zone is globally unique (F16); per-hostname config; one property still untested.
     - `headerIn` on `CDN-PullZoneId` — opaque-identifier match (§4.1.1), per-zone config, no
       dependence on hostname-registration semantics.
     - `headerEquals` shared secret via a per-zone Edge Rule — the strongest simple binding, and
       the only one depending on a secret we hold rather than on a provider property. Remains
       optional; its operational cost is that every Pull Zone must be configured correctly.
   - Note the attacker does not need a matching hostname to *reach* the right router: a zone's
     origin-Host override lets them present any `Host` to Traefik. That is why `hostExact` only
     helps if `CDN-Host` is genuinely unaffected by that override — the second untested property.
   - Test 1 (global hostname uniqueness) is **done and positive**: re-registering an in-use
     hostname on a second Pull Zone is rejected. One test remains, and it gates only `hostExact` on
     `CDN-Host`: set the origin Host header override (or an Edge Rule setting `Host`) on the
     disposable zone and check whether `CDN-Host` follows it or stays at the routed hostname.
   - `*.b-cdn.net` / `*.bunny.run` are **not** an ownership namespace; see §4.2.
5. **Poisoned feed** (DNS hijack, MITM, provider compromise) — HTTPS with default validation, the
   §5 corruption guards, and LKG retention. Genuinely new surface relative to a static list; stated
   rather than hidden.
6. **IPv4-mapped IPv6** used to evade a ban → always `Unmap()`.
7. **IPv6 zone identifiers** → stripped.
8. **Duplicate header instances** → rejected (§7).
9. **Feed outage as a lever** → LKG means trust behaviour does not shift under refresh failure.
10. **Yaegi interpretation cost** as soft DoS → hot path is one map lookup, ≤22 prefix comparisons,
    and a handful of header operations.

---

## 10. Test strategy

Plugin is ordinary Go; unit tests run natively.

**Resolution unit tests** (table-driven over `(peer, headers, sources) → (client, action)`):
- direct v4 / v6, no headers → `client = peer`, `RemoteAddr` **unchanged**
- direct with spoofed `X-Real-IP`, XFF, `CF-Connecting-IP`, `True-Client-IP`, `Forwarded` and
  `X_Real_IP` → **client-identity headers removed**, canonical `X-Real-Ip` set to the peer,
  `client = peer`
- direct with spoofed `CDN-Host` and `CDN-RequestCountryCode` → **passed through byte-identical**;
  they are provider metadata, not client identity, and the plugin does not strip them (§6.3). The
  forged `CDN-Host` must not cause a trust match, because no peer-address predicate matched
- trusted path with `hostExact`/`hostSuffixes`/`headerIn` configured over `Cdn-Host` /
  `Cdn-Pullzoneid` → predicate evaluated **and the header still reaches `next` unmodified**;
  inspecting a header is never a reason to delete it (§6.2)
- Bunny-like: peer in set + `X-Real-IP` v4 → extracted; v6; `::ffff:1.2.3.4` → unmapped
- Bunny-like with header missing / empty / whitespace / garbage / `"1.2.3.4, 5.6.7.8"` / duplicate
  instances / private address → **403** in each case
- Cloudflare-like via `CF-Connecting-IP`
- both providers configured; peer matches CF only; peer matches neither → direct
- overlapping ranges → first source wins, deterministically
- `headerEquals`: correct secret → trusted; wrong secret + peer in range → 403; wrong secret + peer
  out of range → direct
- `headerEquals` as a source's **sole** predicate (no `static`/`feeds`): correct secret from an
  arbitrary peer → trusted; absent/wrong → direct
- `headerIn` on `Cdn-Pullzoneid`: exact byte match → trusted; `"6498612 "`, `"06498612"` and
  `"6498612."` → 403 (proves no hostname normalization is applied, §4.1.1)
- `trust` composition: `static`+`feeds` union (peer in either → predicate holds); `feeds AND
  headerEquals` requires both; empty `trust` → **config error at startup**
- **each predicate valid standing alone** — one case per predicate (`static`, `feeds`, `headerIn`,
  `hostExact`, `hostSuffixes`, and `headerEquals` at v1.1): configured as a source's only predicate,
  a matching request is trusted and a non-matching one is not. Asserts the plugin imposes no
  anchor requirement (§4.1)
- `hostSuffixes`: `a.lochnair.net` and `lochnair.net` match; **`evil-lochnair.net` does not**;
  `A.LOCHNAIR.NET` matches; `a.lochnair.net.` matches; `a.lochnair.net:443` matches; header missing
  → 403; config validation **rejects** a `b-cdn.net` / `bunny.run` suffix
- `hostExact`: exact match (case-insensitive, trailing dot and port stripped) → trusted;
  near-miss (`evil-btest.oandc.fun`, `btest.oandc.fun.evil.com`) → 403; header missing → 403;
  header present more than once → 403
- **multi-provider**: Bunny source with `hostSuffixes` + Cloudflare source without, both active;
  a Bunny peer failing the suffix → 403 while a Cloudflare peer on the same instance still resolves
  normally (proves predicates are per-source, not global)
- **`RemoteAddr` output**: `1.2.3.4:0` and `[2001:db8::1]:0`; assert `net.SplitHostPort` succeeds
  (the F4 guard)
- assert the full delete list is absent and `X-Real-Ip` equals `client`; **on rejection `X-Real-Ip`
  is unset** (the §8.2 log-drop precondition)
- **header-role matrix (§6.2)**, on both the trusted and direct paths:
  - identity headers (`extract.header` + the fixed list) → **removed**, single canonical `X-Real-Ip` set
  - `trust.headerEquals` secret header → **stripped after use**, never reaches `next`
  - `trust.headerIn` / `hostExact` / `hostSuffixes` headers (`Cdn-Pullzoneid`, `Cdn-Host`) →
    **present and byte-identical** at `next`; inspecting must not delete
  - all other `CDN-*` metadata → passed through untouched on every path

**Feed unit tests:**
- parse `lines` (bare IPs, CIDRs, comments, CRLF, trailing blank, BOM) and `json-array`
- validation rejects and retains LKG: empty, below `minEntries`, `0.0.0.0/0`, `10.0.0.0/8`, prefix
  below floor, one unparseable entry among many
- 500 / timeout / TLS failure / truncated body → LKG retained; 304 → no swap, no error
- disk cache round-trip; corrupt cache ignored, not fatal
- two sources sharing a URL → one updater; `New()` 100× → still one goroutine per URL
- concurrent readers during a swap see old or new, never partial

**Integration (docker-compose, real Traefik):**
- normalizer pinned as entrypoint middleware + echo backend; assert backend-observed XFF and
  `X-Real-Ip`
- fake "CDN" container injected via `trust.static`, replaying Bunny-shaped and CF-shaped requests
- **acceptance test A (remediation)**: real CrowdSec, ban `1.2.3.4`, Bunny-shaped request with
  `X-Real-IP: 1.2.3.4` from the fake CDN → 403; non-banned IP → 200
- **acceptance test B (detection, new)**: with `insecure: true`, send a *direct* request carrying
  `X-Forwarded-For: <victim>` and trigger a scenario; assert the resulting CrowdSec decision names
  the **real peer**, not the victim. This is the §8.2 regression and the most important new test.
- assert the JSON access log contains `request_X-Real-Ip` equal to the normalized client
- **plugin-rejected request** (trusted peer, missing identity): assert the access-log line has
  `RouterName` **present** and `request_X-Real-Ip` **absent**, and that CrowdSec creates **no
  decision** for either the POP or any forged XFF value — §8.2 row three
- **unmatched request** (Host matching no router, sent with a forged `X-Forwarded-For` under posture
  B): assert the access-log line **omits `RouterName`**, and that CrowdSec derives `source_ip` from
  `ClientAddr` — the real socket peer, **not** the forged XFF. Repeat with an IPv6 peer to confirm
  the bracketed-`ClientAddr` extraction (F18). This is the probe-detection regression
- direct request from a banned IP → 403 (direct path not broken)
- mTLS route: cert presented → mtlswhitelist allows, **and** its IP-range rule still matches (F7)
- WebSocket and native gRPC through the full chain (the HAProxy H2 regression)
- 20 config reloads → goroutine count stable

**Remaining optional experiment** (§9.4): whether `CDN-Host` reflects the routed hostname or a
zone's origin-Host override. It gates only whether the opt-in `hostExact` predicate is worth
enabling, not v1 scope. The other two Bunny hostname questions are settled: no DNS-ownership
verification on registration (F16, negative), and global hostname→zone uniqueness (F16, positive).

---

## 11. Traefik / plugin limitations to accept

- **No shutdown hook** for plugin middlewares → deduped, immortal updater goroutines.
- **`New()` runs on every config reload** → init idempotent; the single bounded synchronous fetch
  happens at most once per URL per process.
- **Yaegi is interpreted** → hot path stays trivial; drives the hybrid exact-set/prefix-list.
- **Entrypoint model middlewares live in static config** → adding/removing the normalizer
  entrypoint-wide needs a restart. Mostly a feature: it cannot be dropped by a dynamic-config edit.
- **Child routers (`ParentRefs != nil`) do not receive entrypoint model middlewares**
  (`aggregator.go:330`). Confirm Pangolin emits none.
- **Posture B widens the plugin's responsibility** from identity to all forwarded-header hygiene,
  including the TLS client-cert headers.
- **`ClientHost` / `ClientAddr` are unreachable from a plugin** (F10). Access-log aesthetics stay
  out of scope; CrowdSec correctness is handled via the header channel (§8), not by fixing the log.
- **A provider plugin cannot help**: `forwardedHeaders` is static config; provider plugins emit only
  dynamic config.
- **No Traefik fork is needed.**

---

## 12. Phased plan

**v0 — remaining spike (small; the Bunny header spike is done)**
1. ~~Bunny hostname tests~~ — **done** (F16): no ownership verification on registration; hostname →
   Pull Zone is globally unique. One optional follow-up remains (§9.4, origin-Host override) and it
   gates only the opt-in `hostExact` predicate, not v1.
2. Confirm F1 end-to-end with a 20-line logging plugin behind a stock entrypoint.
3. Confirm F10 end-to-end: set a header in that plugin, verify it appears as `request_<Name>` in the
   JSON access log. This underwrites all of §8.

**v1 — minimal and reliable**
- ordered `sources`; trust predicates **`static`, `feeds`, `headerIn`, `hostExact`, `hostSuffixes`**
  (all composable, all off by default except what a preset supplies, §4.1); `extract.mode: single`
  only. `headerEquals` is **v1.1** — it is the only predicate needing secret loading and
  constant-time comparison, so it is separated from the pure set-membership ones.
- `bunny` and `cloudflare` presets as pure data
- feed subsystem per §5 as trimmed: deduped registry, ticker + jitter, ETag, strict parsing,
  fixed corruption guards, atomic swap, LKG, disk cache, one bounded synchronous first fetch
- normalization: `RemoteAddr` → `client:0` (normalized) / untouched (direct); full delete list;
  canonical `X-Real-Ip`; `CDN-*` left untouched (§6.3)
- fail-closed matrix (§7)
- `entrypointForwardedHeaders` flag selecting posture A or B hygiene
- **§8 shipped as part of v1, not deferred** — access-log field, the `source_ip` parser, and the
  drop-on-missing-header whitelist. Without these, adoption makes CrowdSec worse, not better.
  The CDN-range detection whitelist is **optional** belt-and-braces for the cold-start window
  (§8.2), not required machinery.
- structured logging, one line per rejection
- docs: exact entrypoint, access-log, CrowdSec, Badger and Middleware Manager configuration

**v1.1**
- **`trust.headerEquals`** with constant-time comparison and `valueFrom: file:` — the only trust
  predicate deferred past v1; enables the `feeds AND headerEquals` posture and the
  authenticated-header-only source shape shown in §4.1
- counters surfaced via periodic log summary (plugins cannot register Prometheus collectors)

**v2 — only on concrete need**
- **Provider-account inventory as a trust source.** `GET https://api.bunny.net/pullzone?perPage=1000`
  with an `AccessKey` returns Pull Zone IDs and the hostnames belonging to each zone. A trust source
  could periodically derive the set of valid Pull Zone IDs and exact hostnames **from the account
  itself**, giving:
  ```
  peer ∈ Bunny edge feed  AND  CDN-PullZoneId ∈ my account  AND  valid X-Real-IP
  ```
  with no per-zone Traefik maintenance — architecturally the nicest answer to §9.4.
  **Not in v1.** The blocker is credential scope: Bunny currently exposes an account-wide
  management API key, not a read-only Pull Zone credential. Putting an account-wide key into
  Traefik purely for provenance checking is an unattractive trade. Revisit if Bunny gains scoped
  credentials, or if a deployment explicitly accepts the risk.
  Shape v1's `trust` interface so a predicate can be backed by a periodically-refreshed set rather
  than a literal list — that costs nothing now — but **do not build a generic provider-inventory
  framework in advance** merely because this idea exists.
- `extract.mode: xff-rightmost-untrusted` with an explicit inner-proxy pool
- RFC 7239 `Forwarded` parsing
- HMAC / timestamped origin auth
- per-source proto header override
- feed hardening deferred from v1: shrink heuristics, configurable floors, backoff

**Explicit non-goals**: access-log `ClientAddr`/`ClientHost` rewriting, overlap arbitration beyond
list order, arbitrary chain depth, PROXY protocol, per-provider code paths.
