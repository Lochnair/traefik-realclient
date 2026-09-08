# traefik-realclient — design and implementation plan

**Revision:** 2026-09-08. **Status:** planning; no middleware implementation.

> Determine the effective client IP behind configurable trusted upstreams as accurately and
> generically as practical, then normalize the request so downstream middleware can consume
> that identity without provider-specific knowledge.

This is an identity resolver, not an authorization engine. Failure to resolve a more informative
identity normally means using the immediate peer. Neither a missing header nor an unavailable
feed is, by itself, a reason to reject an HTTP request.

Bunny motivates dynamic address feeds; Cloudflare and internal proxies demonstrate the generic
model. Multiple providers, overlapping sources, direct clients, private networks, and mTLS routes
must coexist. Provider presets contain configuration data, not special request-processing code.

The upstream source findings and previous Bunny measurements are recorded in Appendix A.
Measurements are evidence for the tested configurations, not a guarantee about every provider
feature. Proposed runtime behavior below still requires the validation in §9.

## 1. Contract and limits

For every ordinary request on which Realclient runs:

1. Capture the original peer from `req.RemoteAddr`, never a forwarding header.
2. Try configured sources in order, using that same peer and the original headers.
3. Select the first source whose predicates all hold and whose client-IP extraction succeeds.
4. If none succeeds, use the peer.
5. Resolve scheme from the selected source's configured metadata, otherwise from peer transport.
6. Remove competing identity/forwarding inputs, publish canonical headers and a valid
   `RemoteAddr`, and call the next handler.

The useful invariant is **one effective identity**, including when that identity is only the peer.
An accepted source says the configured provenance assumptions were satisfied; it does not prove
the extracted address is a unique human, globally routable, or authenticated to a provider account.

Realclient does not change `req.TLS`, `req.Host`, URL, method, body, or response writer. It does
not buffer a body or wrap the connection. HTTP/2, gRPC, and WebSocket handling remain Traefik's job.
TCP passthrough and UDP traffic do not execute HTTP middleware. Protocol handling alone does not
make WebSocket messages or streaming gRPC messages receive a new identity decision: resolution is
per HTTP request/handshake, not per message.

Here, "peer" means the address Traefik supplies at middleware entry. Normally this is the socket
peer. If PROXY protocol or another earlier transport component replaces it, that component's
configuration becomes part of the provenance boundary. Implementing PROXY protocol is out of scope.

V1 does not reject a request for failed source matching, invalid upstream identity, invalid scheme
metadata, or missing feed data. An unparsable `RemoteAddr` is a different case: no usable fallback
exists. Clear identity inputs and return 500 without calling downstream handlers or echoing the
address. This is a host/integration error, not a strict resolution policy.

## 2. Traefik placement and input preservation

### 2.1 Where the middleware runs

Configure Realclient first in the entrypoint's default HTTP middleware list, using a qualified
dynamic middleware name:

```yaml
# Traefik static configuration; plugin registration/module version is deployment-specific.
entryPoints:
  websecure:
    address: ":443"
    forwardedHeaders:
      insecure: true
    http:
      middlewares:
        - realclient@file
      aliasHeadersStrategy: delete
```

Entrypoint defaults are prepended to root routers. A root's middleware chain wraps its child
router muxer, so children and the child muxer's 404 inherit that execution. Do not attach a second
Realclient instance to children: after the first rewrite, `RemoteAddr` no longer identifies the
upstream peer. Duplicate placement is unsupported, not a mechanism for deeper chain walking.
A second instance can lose source scheme metadata and fall back to peer TLS; with different
sources it may also change identity again. Do not assume idempotence.

Defaults also apply to internal root routers on those entrypoints, including API, dashboard,
ping and ACME HTTP routers where configured. A middleware construction failure can make those
routers unavailable too. Internal traffic is not an automatic exception to deployment coverage.

This is first **configured middleware**, not first request processing:

- Root routing, including root `ClientIP` and header rules, happens before Realclient.
- Access-log collection starts outside configured router middleware.
- Internal router checks can reject before Realclient.
- An entrypoint-level unmatched 404 does not execute router middleware at all.
- Child rules execute after the parent middleware chain and therefore see its normalized address.

Do not use root forwarding-header matches as though this plugin had already authenticated them.
Adding/removing the static middleware reference needs a restart; changing or removing the dynamic
definition is still possible. A static reference does not make the dynamic middleware immutable.

### 2.2 Preserve an input before trying to resolve it

Traefik's secure forwarded-header handler deletes managed headers from untrusted peers, including
`X-Real-Ip` and XFF, then fills an empty `X-Real-Ip` from the peer. No router middleware can recover
an identity already destroyed there.

Deployment choices:

| Deployment | Identity input | Consequence |
|---|---|---|
| Dynamic upstreams using managed headers, including stock Bunny | `forwardedHeaders.insecure: true` | Preserves input; Realclient normalizes it on its execution paths. Pre-plugin consumers still see untrusted input. |
| Secure entrypoint with no native trusted ranges | Non-managed authoritative header; Bunny needs an origin rule copying the client identity to one | A missing custom header leads to peer fallback. Cloudflare's normal `CF-Connecting-IP` needs no renaming. |
| Secure entrypoint with native `trustedIPs` | Managed headers from those native trusted peers | Supported, but the address list is static and requires restart to change. |

In either posture, Traefik removes non-managed headers named by `Connection` before plugins run.
Preserve required identity, scheme and selector inputs by ensuring the upstream normalizes
`Connection`, or listing those names in the entrypoint's `forwardedHeaders.connection` allowlist.
Allowlisted nominated headers survive the middleware chain but remain nominated for hop-by-hop
removal before the backend; allowlisting is not an authenticity guarantee. Cloudflare documents
Connection normalization; the tested Bunny path has not established this behavior. Test custom
proxies explicitly. Deleting a selector can cause another source to win, not just peer fallback.

A separate ingress port is also a legitimate deployment choice, not inherently a fail-open bug.
Choose based on topology and operational cost. Realclient does not enforce or discover the static
entrypoint posture. There is no `entrypointForwardedHeaders` plugin flag in v1: the same explicit
normalization runs in every posture, eliminating two divergent sanitization paths.

There are two unavoidable ambiguities:

- An absent/empty incoming `X-Real-Ip` can arrive at Realclient as the peer because Traefik filled
  it. Accepting that valid value selects the source and stops the search, even when a later
  source could supply a more informative IP. Put broad fallback sources after those sources.
  Do not reject equality with the peer or continue specially on equality: a legitimate equal
  identity and that source's scheme metadata still have the configured precedence. Supplied
  malformed or duplicate X-Real-Ip values can still fail extraction.
- Traefik can similarly synthesize a missing `X-Forwarded-Proto`. A trusted source using this
  managed header cannot distinguish synthesis from supplied metadata. Use a provider-controlled
  non-managed header if distinguishing absence is required.

Traefik also fills empty forwarded host/port, overwrites X-Forwarded-Server, joins multiple XFF
instances, and synthesizes `ws`/`wss` for WebSocket upgrades. Extraction and cardinality tests
must exercise what reaches the plugin, not assume the original wire representation survives.

The insecure setting is useful for stock Bunny, but optional log detection must follow §8 rather
than blindly consuming the stock CrowdSec `ClientHost` attribution.

## 3. Configuration and source selection

### 3.1 V1 configuration

```yaml
# Traefik dynamic configuration.
http:
  middlewares:
    realclient:
      plugin:
        realclient:
          feedCacheDir: /var/lib/traefik/realclient
          sources:
            - name: bunny
              preset: bunny
              # Optional selection, not required by the preset:
              # trust:
              #   headerIn:
              #     name: Cdn-Pullzoneid
              #     values: ["6498612"]
            - name: cloudflare
              preset: cloudflare
            - name: internal-lb
              trust:
                static: ["10.42.0.0/16"]
              extract:
                header: X-Real-Ip
                mode: single
              scheme:
                header: X-Forwarded-Proto
                mode: single
```

Top-level fields are `sources` (ordered list, default empty) and `feedCacheDir` (default empty,
disabling persistence). An empty source list is useful as a peer-only normalizer.

Source fields are `name`, `preset`, `trust`, `extract`, and optional `scheme`.
Names are nonempty and unique within an instance. No automatic name or preset is inferred.
Every expanded source needs at least one effective trust predicate and a complete
`extract: {header: ..., mode: single}` object. Both extraction fields are required.

### 3.2 Deterministic preset overlay

Only this documented overlay exists; there is no general deep merge:

- Copy the preset into independent instance-owned data.
- Within `trust`, each explicitly supplied predicate replaces that entire predicate; omitted
  predicates retain the preset's value. The peer family has two separately replaceable list
  fields, `static` and `feeds`.
- Lists replace, never append. An explicit empty `static` or `feeds` list clears that list.
- `extract` and `scheme`, when supplied, replace their entire objects. `scheme: {}` disables
  source scheme extraction. A nonempty scheme object must be complete.
- `trust: {}` adds/overrides nothing; it does not clear inherited predicates. To discard a
  preset's provenance assumptions altogether, write a source without `preset`.
- An explicitly empty header predicate is invalid, not an instruction to disable it.
- Explicit null values are invalid everywhere. Validate the final expanded source.

Thus `preset: bunny` plus `trust.headerIn` retains Bunny's feeds and adds one AND condition.
An inline list of feeds replaces the preset list in full, including its IPv6 member. Operators
must supply both if both are wanted.
Clearing feeds while retaining only header predicates removes peer-address anchoring. This is
legal but requires an independent provenance guarantee; see §3.4's construction diagnostic.

### 3.3 Strict decoding at the plugin boundary

Traefik's mapstructure adapter uses weak conversion and does not reject unused keys. Ordinary
typed structs with ignored unknown fields are insufficient for this configuration.

Plan a raw map-based external config returned by `CreateConfig`, followed by explicit recursive
validation and conversion into typed, immutable internal settings in `New`. Treat the supplied
map and everything reachable from it as shared, read-only data: the adapter can retain references
to Traefik's runtime configuration. Build independent internal
settings, deep-copying any intermediate data that must be transformed; never overlay in place.
The Yaegi spike must verify this exact boundary with Traefik's adapter. Preserve unknown keys and
original scalar types until validation; do not silently coerce numeric identifiers, booleans, or lists. If a
provider has already converted a value to a string, original file bytes cannot be reconstructed.

Validate field names against the exact documented spelling, including nested maps and list
elements. Reject unknown keys, unknown presets/modes, unsupported versioned fields, nulls,
incorrect scalar/list shapes, empty required strings, and invalid header names. A v1 config
containing `headerEquals` must fail clearly, not silently become feed-only trust.

Durations are strings parsed explicitly with `time.ParseDuration`, positive and at least one
second; there is no assumed mapstructure duration hook. Numeric durations are invalid. The
documented YAML lists remain lists. Integer fields such as `minEntries` accept either an integral
numeric value or an ASCII decimal digit string, checked for range before conversion; reject
non-finite/fractional numbers, signed or whitespace-padded strings, exponent strings and overflow. This is field-specific:
identifiers and durations must remain strings, and arbitrary strings never become lists.
V0 must test file and label/KV provider representations through the actual adapter, including
indexed source/feed lists and empty-list overlays. Support is limited to providers that preserve
these documented shapes; publish tested syntax and explicit limitations before claiming support.
Do not silently relax validation to accommodate a provider. Boolean coercion is not needed by
the v1 schema.

V1 has no `allowPrivateClient`, `setRealIP`, `onTrustedButInvalid`, or configurable rejection
status. These old fields are rejected as unknown with migration guidance.

Validate the whole instance before starting new feed workers. Invalid config fails construction
of that middleware; do not describe this as necessarily terminating the Traefik process or
preserving its old dynamic routing configuration.

### 3.4 Trust predicates

All configured predicates on one source must hold:

| Predicate | Meaning |
|---|---|
| `static: [IP-or-CIDR, ...]` and `feeds: [FeedSpec, ...]` | Together ONE predicate: original peer belongs to the union of all static addresses and currently available feed sets. |
| `headerIn: {name, values}` | One parsed header value equals an element of an exact, case-sensitive string set. |
| `hostExact: {header, values}` | One normalized hostname equals an element of the normalized hostname set. |
| `hostSuffixes: {header, suffixes}` | One normalized hostname equals a suffix or ends with a dot plus that suffix. |

There is at most one of each header predicate per source in v1. Nonempty lists are required for
header predicates. Every predicate may stand alone; no peer-address or secret anchor is imposed.
Header-only trust is appropriate only when the deployment independently guarantees that header's
provenance. A public client can otherwise send a matching value.
Emit a construction-time warning naming each source without a peer-address predicate, without
logging predicate values. No extra acknowledgement flag or mandatory peer anchor is imposed.

Empty static/feed lists contribute nothing. The peer-address predicate exists only if at least
one static entry or feed specification remains after overlay; an unavailable configured feed
still counts as configured, but its current set is empty. If clearing lists leaves no effective
predicate of any kind, reject the source at construction rather than treating empty trust as true.

No provider/domain blacklist is built into generic hostname validation. A suffix is a namespace
selection rule, not evidence of ownership. Public-ingress Bunny guidance is in §7.

### 3.5 First successful resolution wins

For each source, in list order:

1. Evaluate every configured predicate against the original peer and as-yet-unmodified request.
2. If any fails, continue to the next source.
3. If all hold, parse its configured client header.
4. If extraction fails, continue to the next source.
5. On extraction success, select that source and stop the search.

Only then mutate headers. A failed earlier source never changes what a later source reads.
No remembered partial match can force rejection, override a later success, or prevent fallback.

For two Bunny sources selecting different Pull Zone IDs, a request for the second zone passes
through the first source's non-match and resolves with the second. If both sources fully match,
the first with a valid client value wins. If the first's identity is malformed and the second's
is valid, the second wins. More restrictive sources should precede broad fallback sources when
that is the intended interpretation.

Source selection is not authorization. In particular, a broad later source can intentionally
accept traffic that an earlier account-specific source did not select. Requests that should be
denied need a separate authorization middleware or ingress policy.
Predicate and extraction failures can be induced externally, including by omitted or malformed
headers and Connection nomination (§2.2). Conversely, synthesized X-Real-Ip can turn an omitted
input into a successful source selection. These are ordering/provenance considerations, not
exceptions to first-success selection.

## 4. IP and scheme parsing

### 4.1 IPs and address sets

- Parse the peer using `net.SplitHostPort`, then `netip.ParseAddr`; IPv6 host:port must be
  bracketed. Require a nonempty decimal port in 0–65535. Do not guess around malformed addresses.
- A client identity is exactly one header instance containing exactly one bare IP. Trim outer
  HTTP optional whitespace (space/tab), then parse. Reject empty values, commas, quotes,
  bracketed IPs, host:port, DNS names, and non-IP text as extraction failures.
- Normalize valid addresses by removing an IPv6 zone and unmapping IPv4-mapped IPv6, then
  serializing with `String()`. Zones describe an interface scope, not a portable client identity;
  they are not forwarded and these logical addresses must not be used to initiate connections.
- Private, loopback, link-local, CGNAT, and documentation addresses are permitted. Resolving an
  internal client's IP is legitimate. Reject unspecified addresses, multicast, and the IPv4
  limited broadcast address as extracted identities. Do not equate `IsGlobalUnicast` with
  public Internet reachability.
- Canonicalize any parseable peer, but do not apply the extracted-identity prohibited-address
  checks to it. Even an unspecified peer supplied by an earlier transport component remains
  the fallback, not a Realclient-generated 500; it may be recorded in debug diagnostics.
  Malformed host/port or a non-IP peer still follows §1's integration-error behavior.
- Static entries and feeds use the same IP/CIDR parser. Exact addresses use the host rules above.
  CIDRs have no zones and are masked before storage. A prefix inside the IPv4-mapped /96 space,
  with length 96–128, is converted to IPv4 with 96 subtracted from its length. Reject mapped
  prefixes shorter than /96 as ambiguous. Ordinary IPv6 prefixes retain their family.
- Set membership is over canonical peers: IPv4 prefixes match unmapped IPv4, ordinary IPv6
  prefixes match IPv6. A generic `::/0` does not also mean IPv4; configure both families if wanted.

Use an immutable exact-address map plus a prefix slice. Canonical /32 and /128 entries can go
into the exact map. Deduplicate equivalent entries. This is efficient for the measured presets;
there is no generic guarantee of at most 22 prefix comparisons.

### 4.2 Header and hostname predicates

Predicates compare the values available in Go's request, not original wire bytes. Go's HTTP/1
reader has already trimmed whitespace. `headerIn` applies no additional value normalization;
numeric-looking values remain strings, and `"06498612"` differs from `"6498612"`.

All trust-header predicates require exactly one instance; missing, empty, or duplicate values
mean non-match, not HTTP rejection. A comma has no special list meaning for `headerIn`; only the
configured whole string can match. Host predicates reject comma lists.

Header names use valid HTTP token syntax and are canonicalized case-insensitively. Read named
headers from `req.Header`; for host predicates only, `header: Host` explicitly reads `req.Host`.
Other uses of `Host` are config errors rather than accidental empty header reads.

Hostname normalization, applied identically to config values and request values:

1. Trim outer space/tab; reject internal whitespace, lists, schemes, paths, and userinfo.
2. Use the shared bracket-aware authority splitter also used by §5.2. Remove an optional decimal
   port in 1–65535; reject malformed/empty ports. Bracketed IPs may split successfully but are
   rejected by the hostname policy below.
3. Remove one terminal DNS dot and lowercase ASCII.
4. Require nonempty DNS labels of 1–63 ASCII letters/digits/hyphens, no leading/trailing hyphens,
   and total hostname length at most 253. Reject IP literals, empty labels, wildcards, and
   non-ASCII input. IDNs must be configured and supplied in their ASCII A-label form.

Thus `EXAMPLE.COM.:443` becomes `example.com`. A suffix `example.com` matches both the apex and
`a.example.com`, but not `evil-example.com`. No automatic public-suffix or provider ownership
inference is performed.

### 4.3 Original scheme is independent of peer transport

`req.TLS != nil` describes peer→Traefik TLS. It cannot determine whether client→upstream was
HTTP or HTTPS. Scheme is resolved separately after selecting the IP source; do not select a
different IP source merely because its scheme metadata is missing or malformed.

An optional source `scheme` object has `header` and `mode`:

| Mode | Accepted parsed input |
|---|---|
| `single` | Exactly one header instance containing one token. |
| `uniform-list` | Exactly one header instance containing one or more comma-separated tokens, all agreeing after normalization. |

Trim space/tab around tokens and lowercase. Accept `http` and `https`; accept `ws` and `wss`
as their HTTP and HTTPS transport equivalents. Empty members, unknown tokens, disagreement such
as `https, http`, and duplicate header instances are failures. `https, https` resolves to HTTPS.
This does not assign list positions to network hops or choose a leftmost/rightmost authority.

Only the successfully selected source may supply scheme metadata. The operator must establish
that its configured header is authoritative; peer-range membership alone does not prove a proxy
overwrites client-supplied XFP. If no source succeeds, no scheme is configured, or scheme parsing
fails, use peer transport (`https` for TLS, otherwise `http`) as the best available estimate.
Keep a successfully extracted IP even when scheme falls back.
Disagreement is not a promise against downgrade: HTTPS client traffic over a plaintext origin
connection falls back to HTTP. Authoritative metadata is necessary for accurate original scheme.

Emit `X-Forwarded-Proto` as `http`/`https`, or `ws`/`wss` for an actual HTTP WebSocket upgrade
(Connection contains Upgrade and Upgrade is websocket, case-insensitively). Do not label arbitrary
upgrades as WebSocket. Do not rewrite `req.TLS` to pretend an upstream client's TLS terminated here.
This convention covers HTTP Upgrade handshakes; extended CONNECT without those headers retains
HTTP/HTTPS output. Realclient does not infer WebSocket protocol state from other transports.

For a deployment that must distinguish missing metadata from Traefik's synthesized XFP, use an
authoritative non-managed header. Mixed origin/client schemes and origin Host overrides cannot
be recovered correctly from the origin connection alone.

## 5. Request normalization

The normalization algorithm is identical on successful-source and peer-fallback paths.
Capture resolution inputs first; mutate the existing header map in place before calling next.
Do not replace it with a clone and assume the outer logger follows that replacement.

### 5.1 Identity outputs

- Always set exactly one canonical `X-Real-Ip` to the effective IP; there is no disable switch.
- If a source successfully resolved the IP, set `RemoteAddr = net.JoinHostPort(client, "0")`.
- On peer fallback, reconstruct `RemoteAddr` from the canonical peer and its original port.
  Ordinary direct requests stay equivalent; mapped/zoned spellings become consistent.
- Delete XFF rather than setting it to an empty/nil sentinel. With Traefik's normal
  `notAppendXForwardedFor: false`, the proxy appends the effective `RemoteAddr` host for the backend.

Remove the following competing identity headers on both paths, plus every configured extraction
header from every source, including those not selected:

`Forwarded`, `X-Forwarded-For`, `X-Real-Ip`, `X-Client-Ip`, `X-Cluster-Client-Ip`,
`X-Original-Forwarded-For`, `X-Originating-Ip`, `True-Client-Ip`, `Cf-Connecting-Ip`,
`Cf-Connecting-Ipv6`, `Cf-Pseudo-Ipv4`, `Fastly-Client-Ip`, `Fly-Client-Ip`,
`X-Azure-Clientip`, `X-Azure-Socketip`, `X-Appengine-User-Ip`, `Proxy-Client-Ip`,
`WL-Proxy-Client-Ip`, `X-ProxyUser-Ip`.

Compare header names case-insensitively with underscores treated as dashes when sweeping managed
names, including configured inputs. This handles underscore aliases; it is not a universal
backend-specific header-alias defense. Use Traefik's alias-header strategy where supported.

This finite list cannot know every private application identity header. Configure that channel
as an extraction input or remove it using a dedicated headers middleware. Downstream consumers
must use the canonical identity rather than inventing an independent header precedence.

### 5.2 Forwarding outputs and metadata

Always remove incoming values and underscore aliases for the forwarding outputs below before
writing the stated values. Source scheme inputs are consumed and removed across all sources.

| Header | Output |
|---|---|
| `X-Forwarded-Proto` | Scheme resolved under §4.3, with WebSocket convention where applicable. |
| `X-Forwarded-Scheme`, `X-Scheme` | Rebuild both with the same value as canonical X-Forwarded-Proto. Consistent aliases are always emitted, independently of Traefik's addXForwardedSchemeHeaders setting. |
| `X-Forwarded-Host` | Current `req.Host`; omit if empty. It is the host presented to Traefik, not a recovered original host. |
| `X-Forwarded-Port` | Valid explicit decimal port from `req.Host`, otherwise 443/80 according to the resolved HTTPS/HTTP scheme. This is a best-effort authority port, not proof of the original listener port. |
| `X-Forwarded-Prefix`, `X-Forwarded-Uri`, `X-Forwarded-Method` | Remove. No unverified original path/method is reconstructed. Later path/auth middleware may create its own values. |
| `X-Forwarded-Server` | Preserve Traefik's synthesized value unless consumed as a configured input. It does not compete on client IP or scheme. |
| `X-Forwarded-Tls-Client-Cert`, `X-Forwarded-Tls-Client-Cert-Info` | Remove inbound assertions; a downstream certificate middleware may repopulate from `req.TLS`. |
| `Cf-Visitor` | Remove: it is a competing scheme channel, including for Badger. |

For IPv6 `req.Host`, use bracket-aware authority parsing; do not split on the first colon. If
no valid explicit port is available, use the scheme default; never copy a malformed port header.
An original nonstandard port or host hidden by a proxy override is outside v1's recovery contract.
Traefik itself considers XFP before falling back to origin TLS for the port. A concrete difference
is original HTTP over a TLS origin connection without an explicit Host port: Realclient emits
80, whereas Traefik's transport fallback emits 443. Backends constructing redirects can observe it.

Delegated certificate assertions such as Envoy/Istio `X-Forwarded-Client-Cert` are outside the
IP normalization contract and are not deleted automatically. Their trust belongs to the
deployment's certificate-authentication configuration. The Traefik-specific certificate headers
above are cleared so its downstream certificate producer can publish actual `req.TLS` state.

Preserve ordinary provider metadata such as `CF-IPCountry`, `CDN-Host`, `CDN-PullZoneId`,
`CDN-RequestCountryCode`, `CDN-ServerId`, `Via`, and request IDs, including on direct requests.
Their presence is not an assertion by Realclient that they are authentic.

Deletion precedence is explicit: consumed identity/scheme inputs are
removed even if a trust predicate also read them. Metadata used only for matching is preserved.
Reject a configured extraction/scheme header colliding with `Host`, `Connection`, `Upgrade`,
`Transfer-Encoding`, `Content-Length`, `TE`, `Trailer`, `Keep-Alive`, `Proxy-Connection`,
or an output of the other role; allow the intended identity input `X-Real-Ip` and scheme input
`X-Forwarded-Proto`. Future secret-input precedence is specified in §9's v1.1 scope.

Operators must account for downstream mutation. Badger can repopulate XFF when its own trust
branch is active. A headers/auth middleware can overwrite canonical headers. Realclient cannot
enforce an invariant after arbitrary downstream rewrites; supported ordering/configuration is §7.

## 6. Dynamic feed subsystem

### 6.1 Feed specification and validation

Each `trust.feeds` element is a complete object:

| Field | Meaning/default |
|---|---|
| `url` | Required absolute HTTPS URL; no userinfo or fragment. |
| `format` | Required `lines` or `json-array`. |
| `refreshInterval` | Duration string; default `30m`, minimum `1s`. |
| `minEntries` | Integer in 1–100,000; default 1; count distinct normalized IPs/prefixes. |

Use explicit format, not content-type sniffing. `lines` accepts bare IPs/CIDRs, CRLF, blank lines,
whole lines starting with # after trimming, and one initial UTF-8 BOM. No inline comments.
`json-array` accepts one JSON array of strings, then whitespace and EOF; reject extra JSON,
non-string values, and malformed entries. Both trim entry whitespace and use §4.1's parser.

HTTP success is a fully read 200 body within a fixed 4 MiB decoded-body cap, with at most 100,000
distinct entries, satisfying syntax and `minEntries`. Read enough to detect overflow rather than
silently parsing a truncated prefix of the body. Reject the entire update on any bad entry.
An empty response is failure, not an instruction to erase trust.

There are no hardcoded public-address restrictions, Bunny-domain prohibitions, or /8-/19 prefix
floors. Private feeds and broad aggregates are legitimate. Even /0 is syntactically valid trust
configuration: its publisher can authorize every peer of that family. Such a feed should only be
used if that is actually intended. Counts and parsing detect some accidents, not a compromised
publisher replacing one valid address set with another.

Fetch with normal certificate validation, a 15-second total client timeout, no redirects, no
credential loading, and close response bodies on all paths. Feed URLs are operator configuration,
not derived from requests. Format changes or redirected endpoints require explicit config updates.
Retry failures after two minutes with ±10% jitter; successful refreshes use the configured
interval with the same jitter. Send an identifying `traefik-realclient` User-Agent; this identifies
the fetcher, not a guarantee against provider filtering. No per-request fetches, backoff framework,
or provider-account discovery.

### 6.2 Worker identity and lifetime

Share workers through a mutex-protected package registry, **per Yaegi interpreter/plugin alias**.
Worker identity is the structured tuple:

`(exact URL string, format, parsed refresh interval, minEntries, cleaned absolute cache directory)`.

The parser/cache schema version is also included when deriving a persistent cache key.
Disabled persistence uses the empty string as the cache-directory component.
Identical effective specifications share one worker, irrespective of source/instance name.
Different specifications get different workers; there is no promise of one worker per URL.
This intentionally avoids first-constructor-wins policy and live mutation of another instance's
validation or polling settings.

Each worker owns immutable settings, its HTTP client, one serial fetch loop, and an
`atomic.Value` containing an immutable snapshot. Publish an initialized empty snapshot before
exposing the worker; never type-assert an uninitialized atomic value. Readers never mutate a
published map/slice. Use no generic `atomic.Pointer[T]`.

Insert one worker with its empty snapshot under the mutex and arrange exactly one background
loop. Constructors share that worker and return without waiting for cache or network I/O.
The loop loads and validates cache first, publishes it if usable, then immediately fetches and
enters the refresh schedule. No global lock is held across cache or HTTP I/O. A slow cache can
delay that worker's first fetch, but cannot stall router construction. Requests may use fallback
even with a valid cache while its asynchronous load is pending; no initialization waiters exist.

Workers deliberately live until interpreter/process exit and use a worker-owned background
context with per-fetch deadlines, not the first router's `New(ctx)` context. Traefik cancels
router-construction contexts on reload; attaching shared polling to one would strand other users.
No request or handler is retained by a worker.

Changing the specification creates a new worker. Removing a source immediately removes that
source from new handlers, but its old worker remains polling; old in-flight handlers retain their
own settings. Repeated identical reloads do not add workers. Repeated distinct configurations can
accumulate workers, clients, and cache files until restart. This is a stated v1 lifecycle cost;
routine stable configurations do not need refcounting, teardown watchers, or a scheduler framework.
Different plugin aliases/processes may each fetch the same URL.

### 6.3 Cache, ETag, and last-known-good

Persistence is optional. Require an absolute cache directory when enabled; clean it before keying.
Use a schema-versioned hash of worker identity for the filename, never a URL path. Traefik needs
write permission. An unreadable/unwritable cache is logged and treated as unavailable, not as a
failure of the middleware configuration.
Cache contents are trusted equivalently to middleware configuration: validation cannot establish
their publisher provenance. Protect the directory and its parent path against untrusted writers
or replacement. Restrictive files alone do not protect a writable directory. Legitimate shared
container/group ownership is allowed; no simplistic owner-only permission check is imposed.

Cache one complete validated representation with its identity/schema, normalized entries, ETag,
and last successful validation time. On load, validate identity/schema, size, entries, and current
`minEntries` again. Corrupt/mismatched data is ignored. Stale valid data remains eligible: v1 LKG
has no automatic expiration, and an immediate refresh attempts to replace it.

Publish entries and accepted validator as one coherent snapshot. An invalid 200 must update
neither. Send `If-None-Match` only when there is a usable accepted representation and nonempty ETag.
A 304 retains the set; without a usable representation, retry unconditionally instead of
declaring success. A valid 200 without ETag clears the old validator.
ETag presence does not guarantee an endpoint honors conditional requests. Exercise 304 and
validator transitions with a controlled HTTP server; generic support is independent of whether
the shipped provider feeds currently return 304.

Write cache updates to a unique temporary file in the same directory, sync and close it, then atomically
rename; use restrictive file permissions. A crash can lose a recent update but must not turn a
partial write into accepted trust. Cache-write failure does not discard a valid in-memory update.
Concurrent processes have separate memories; complete atomic file replacement prevents torn
reads but does not promise cross-process freshness ordering. Prefer separate cache directories
for separately managed Traefik processes; no interprocess lock service is added.

### 6.4 Availability is information, not authorization

A source uses the union of static entries and each available feed snapshot. One feed can refresh
while another retains LKG or has never loaded. There is no multi-feed transaction or readiness
barrier. Static membership remains usable even if every feed is unavailable.

An unknown/new edge cannot match a range that has not been learned. That request tries other
sources, then uses its peer IP. Missing one address family can therefore reduce resolution
accuracy for that family. The same limitation exists during cold start, after provider expansion,
or while a stale cache misses new addresses. No guessed recognition or blanket denial fixes it.

LKG preserves availability but also retains removed addresses until a successful refresh;
unbounded stale retention is an explicit tradeoff. Removing a feed/source from config removes
its trust from new handlers even if its worker/cache still exists.

Log feed failures, recovery, cache failures, and new worker settings without response bodies or
credentials. Ordinary per-request fallback is normal operation; do not emit an ERROR for every
direct request. Optional debug diagnostics may record source/failure reason and peer without
dumping headers. Metrics/counters can follow later.
Failure diagnostics distinguish empty snapshots from retained LKG and include its validation age;
rate-limit repeated warnings per worker, and report recovery. A below-minimum update leaves the
previous accepted snapshot/cache intact. At unchanged settings, it does not invalidate an old
cache that still satisfies the minimum, nor another feed belonging to the same source.

## 7. Presets and downstream compatibility

### 7.1 Provider presets

```yaml
# preset: bunny
trust:
  feeds:
    - url: https://api.bunny.net/system/edgeserverlist/plain
      format: lines
      refreshInterval: 30m
      minEntries: 1
    - url: https://api.bunny.net/system/edgeserverlist/ipv6
      format: json-array
      refreshInterval: 30m
      minEntries: 1
extract: {header: X-Real-Ip, mode: single}
# No default authoritative scheme assumption; see below.

# preset: cloudflare
trust:
  feeds:
    - url: https://www.cloudflare.com/ips-v4
      format: lines
      refreshInterval: 12h
      minEntries: 1
    - url: https://www.cloudflare.com/ips-v6
      format: lines
      refreshInterval: 12h
      minEntries: 1
extract: {header: Cf-Connecting-Ip, mode: single}
scheme: {header: X-Forwarded-Proto, mode: single}
```

Presets use the generic nonempty minimum. Today's feed counts are not a contractual lower bound;
legitimate consolidation must not silently freeze updates. Operators may set higher `minEntries`
with an explicit understanding that rejected updates retain LKG and can prevent cold-start use.

**Bunny:** prior measurements establish overwrite behavior for IP headers in the tested stock
path. They also observed `https, https` for XFP with Edge Rules/Scripting active; neither its hop
meaning nor resistance to client influence was established. The preset therefore does not
silently authenticate XFP. A deployment that establishes authoritative scheme forwarding can add:

```yaml
scheme: {header: X-Forwarded-Proto, mode: uniform-list}
```

Alternatively, set a non-managed scheme header from trusted edge metadata and use `single`.
Until then the preset uses origin transport as an acknowledged estimate. Independently measuring
stock Bunny scheme overwrite behavior could justify adding a scheme default in a later revision.

**Cloudflare:** the single-header preset requires Pseudo IPv4 not to use "Overwrite Headers",
otherwise `CF-Connecting-IP` is synthetic and the real IPv6 is in `CF-Connecting-IPv6`.
Disable that mode rather than adding a provider-specific fallback branch in v1. Header-removal
transforms cause peer fallback. Same-zone Workers can alter the identity feeding
`CF-Connecting-IP`; cross-zone Worker subrequests use Cloudflare's documented shared Worker IP.
The preset cannot invent the missing visitor identity. Cloudflare explicitly documents replacing
client-supplied XFP with the client protocol; that published contract supports the scheme default.
Original XFP is useful only if Traefik's
entrypoint preserved it; with secure stripping use a trusted non-managed equivalent or accept
the origin-transport estimate.

Provider feed membership means "this peer is in the published set," not "this request belongs to
my account." Another Bunny customer can point a zone at the origin and customize identity headers.
This residual provenance assumption is accepted by feed-only deployments.

Optional Bunny selection:

- `headerIn` on `CDN-PullZoneId` selects configured zones.
- `hostExact` on `CDN-Host` selects registered names; its account-binding interpretation still
  depends on the untested origin-Host override behavior in Appendix A.
- `hostSuffixes` filters a namespace but is not ownership proof: Bunny accepted unverified
  custom names. The shared `b-cdn.net`/`bunny.run` namespaces identify no particular account.
- A shared-secret header may be supported in v1.1; it is neither required nor emulated by storing
  a secret in `headerIn` (which has different logging/comparison semantics).

On public ingress, pair provider metadata selection with provider peer ranges. Metadata-only
selection remains legal for deployments with an independent provenance guarantee.

### 7.2 Request-time consumers

Use `Realclient → CrowdSec → Badger/other auth → backend`, with any Traefik certificate-header
producer after Realclient. No intervening middleware should restore an untrusted identity channel.

**CrowdSec bouncer/AppSec:** keep the default forwarded header name `X-Forwarded-For`.
No CDN ranges need to be added to `forwardedHeadersTrustedIps`; with XFF absent the inspected
bouncer falls back to `RemoteAddr`. AppSec uses the same resolved address.
`clientTrustedIps` is a separate enforcement bypass, not upstream trust; leave it empty unless
that bypass is explicitly desired. If resolution fell back to a POP, enforcement necessarily
uses the POP too. The middleware cannot recover an unavailable end-user identity.
This includes first boot with feeds-only presets, unavailable cache/network, and the asynchronous
cache-load window. The bouncer alone does not create a persistent ban from a traffic burst;
log detection or configured AppSec remediation determines that behavior. When such detection is
enabled, peer attribution can lead to shared-upstream decisions (§8.3). Operator-maintained static
seeds or detection exclusions can mitigate this, but are optional, incomplete and independently
maintained—not a prerequisite or a mandatory bouncer bypass.

**Badger:** recommend `disableDefaultCFIPs: true`, `trustip: []`, `customIPHeader: ""`.
It then uses the normalized address without reinterpreting CDN headers or rebuilding XFF.
Its default trust branch can run whenever the effective client belongs to those CIDRs; this
statement does not rely on an unverified claim that all WARP egress ranges equal CDN ranges.

**mtlswhitelist:** canonical `X-Real-Ip` supports its IP-range rule. Its certificate branch reads
`req.TLS.PeerCertificates`, which is untouched. Test the no-certificate IP rule separately from
the certificate branch. Existing Traefik TLS options still govern requesting/verifying client
certificates; a certificate from a CDN connection is not the original user's certificate.

**Backends:** with normal Traefik XFF append and no intervening header reconstruction, receive a
single effective-IP XFF entry and canonical X-Real-Ip. Preserve body streaming, trailers and
upgrade mechanics as provided by the supported Traefik release; Realclient adds no protocol proxy.

## 8. Optional CrowdSec detection from Traefik access logs

This section is a separate deployment recipe, not a Realclient feature or adoption prerequisite.
Running the bouncer does not require acquiring Traefik logs. If those logs are acquired under
insecure forwarding, however, the stock parser's header-influenced `ClientHost` is not a safe
source for automatic decisions. Either install an attribution recipe or do not use that stream
for IP decisions.

### 8.1 What the log actually says

| Field | Meaning |
|---|---|
| `ClientAddr` | Pre-router-middleware peer address, including port; subject to earlier transport configuration, not incoming HTTP identity headers. |
| `ClientHost` | Pre-middleware value, overridden by incoming XFF when present. Do not use it for this integration. |
| `RouterName` | Router execution metadata, including parent/child chains. Presence alone does not prove Realclient ran. |
| Entrypoint field | Identifies the ingress entrypoint for the coverage set below; it does not prove middleware execution. Verify the actual serialized field spelling in the pinned logger. |
| `request_X-Real-Ip` | Header map value at logging time. It can be normalized, Traefik-synthesized, or client-supplied on a bypass path. |

Realclient always emits a canonical peer identity on ordinary resolution failure. There is no
need to signal failure by deleting X-Real-Ip, distinguish "direct" from "unresolved proxy" using
a marker, or make the HTTP request fail so that the parser can classify it.

### 8.2 Minimum recipe for effective-IP attribution on covered paths

No response marker is required if the deployment accepts an explicit, tested coverage contract:

1. Configure an explicit set of covered entrypoints in the local parser. Realclient is first
   configured middleware on every root router on those entrypoints and runs once, including
   internal API, dashboard, ping and ACME HTTP routers where present. No later middleware
   replaces canonical identity with untrusted data. Acquiring logs from additional entrypoints
   does not add them to the covered set; their identity headers remain unusable for attribution.
2. Retain required core fields and the canonical request header:

   ```yaml
   accessLog:
     format: json
     fields:
       defaultMode: keep
       headers:
         defaultMode: drop
         names:
           X-Real-Ip: keep
   ```

3. Install **one local replacement JSON Traefik parser in s01-parse**, retaining the stock
   parser's other useful HTTP fields but replacing attribution with the table below. Disable
   the stock Traefik parser for this acquisition; do not run both and hope filename order fixes
   the result. Keep normal s02 enrichment/whitelists after the local parser.
4. Exclude status 400 and 421 events from IP decisions. These are the verified ordinary
   pre-configured-middleware router rejections: recursion/encoded path (400) and SNI mismatch
   (421). Conservatively exclude statuses below 200, 5xx, and missing/malformed status too;
   protocol transitions and abnormal error paths are outside this small recipe.

The local parser applies these rules in order, before setting `remote_addr`/`source_ip`:

| Event | Attribution/action |
|---|---|
| Excluded/invalid status or malformed required JSON fields | Discard from the detection pipeline. |
| Entrypoint field missing/invalid | Discard; coverage cannot be determined. |
| Entrypoint outside the covered set | Parse the host from ClientAddr; ignore identity headers. A deployment may instead exclude these peer-attributed events under §8.3. |
| Covered entrypoint, RouterName absent/empty | Parse the host from ClientAddr; ignore X-Real-Ip and XFF even if present. |
| Covered entrypoint, RouterName present, valid single canonical X-Real-Ip | Use that header as the effective IP under the coverage contract. This includes normal peer fallback. |
| Covered entrypoint, RouterName present, missing/invalid canonical header | Discard; deployment contract failed. Do not guess from ClientHost. |

Set the local parser's `remote_addr` and `source_ip` consistently before moving to s02.
Retain the entrypoint field and test its exact JSON spelling against actual logs; do not substitute
a Go constant identifier for the serialized key. Entrypoint coverage supplements RouterName and
the status exclusions, rather than serving as execution proof by itself.
For discarded events, use a tested parser filter/drop path so they cannot fall into the stock
parser. No source-IP enrichment or whitelist should run first on the old value. Do not use
`onsuccess: next_stage` in an early s02 override that accidentally skips remaining enrichment.

ClientAddr parsing must handle `[2001:db8::1]:443`, normalize mapped IPv4, and remove zones.
Validate header IPs rather than feeding arbitrary text to GeoIP/scenarios. Keep IPv6 addresses
whole; do not use `Split(ClientAddr, ':')[0]`. The local parser must also avoid retaining the
stock parser's broken IPv6 `dest_addr` split or treating ClientAddr as an actual destination.

Why this is smaller than an execution-proof protocol: the resolver now normalizes fallback
requests too, and the known ordinary pre-plugin rejection statuses can simply be excluded.
There is no need for a new request/response header, cryptographic marker, response-writer wrapper,
or additional plugin-to-CrowdSec channel.

The cost is deliberate loss of otherwise legitimate backend/middleware 400, 421, 5xx and upgrade
events. The status exclusions are not a universal proof against new upstream paths, panics, or
incorrect middleware placement. Pin and test the deployed Traefik version and chain; re-audit
when upgrading. Perfect transparent attribution for every Traefik log event is not promised.
The parser recipe is a design contract, not runtime-validated YAML; §9 gates publishing it as a
supported optional integration.

### 8.3 Peer attribution and unresolved upstreams

If the coverage contract cannot be maintained, the simpler trustworthy recipe is a local parser
using the host of ClientAddr for every event and ignoring both ClientHost and identity headers.
This needs no extra logged header, but identifies proxies as proxies rather than recovering users.
Backend logs with known canonical identity are another option; neither is a core design blocker.

Even the effective-IP recipe attributes unmatched CDN probes and unresolved CDN traffic to their
peers. If banning a shared upstream is undesirable, exclude candidate source IPs belonging to a
maintained upstream set before creating decisions. That set is optional integration policy,
independent of Realclient's resolution feeds. It can lag, and unknown edges remain unknowable.
For deployments demanding no upstream bans without reliable ranges, omit peer-attributed
proxy-ambiguous events or use a better log source; do not claim perfect coverage.

The useful three-way distinction is therefore:

- Matched and covered: use the canonical effective identity, whether extracted or peer fallback.
- Unmatched: use the logged peer, independently of request headers.
- Paths that may precede normalization or violate the coverage contract: exclude from IP decisions.

It is no longer "successful normalization versus rejected normalization." Generic resolution
does not need that distinction, and the logs cannot reliably infer every upstream resolution state.

## 9. Validation plan and release boundaries

No tests or implementation are added by this design revision.

### V0 — feasibility and contract tests, before committing to implementation details

- Load a minimal plugin through the intended Traefik release/Yaegi runtime and actual config
  adapter. Exercise raw-map validation, nested lists, unsupported fields, durations, preset
  overlay, netip map keys, atomic.Value, goroutines and concurrent construction.
  Test two routers using the same middleware, including concurrent/repeated construction:
  deep-compare the original nested config before and after, and verify independent results.
  Verify file and label/KV forms, decimal minEntries strings, invalid numeric forms and list
  representations; publish only the provider syntaxes actually demonstrated.
- Demonstrate secure stripping and insecure preservation, including missing X-Real-Ip becoming
  the peer and missing XFP becoming origin transport. Do not assert missing-header rejection.
- Demonstrate default-middleware placement, child inheritance, child-default 404, entrypoint
  unmatched 404, SNI rejection and encoded-path rejection. Confirm which header/core fields
  actually reach the logger, including buffered access logs.
  Send Connection nominations for identity and selector headers, with and without allowlisting;
  verify later-source selection and fallback. Exercise synthesized X-Real-Ip before a later
  informative source, then reverse their order and assert first-success behavior in both cases.
  Test PROXY-supplied `0.0.0.0:0` fallback separately from LOCAL, which preserves the real peer.
- Confirm the intended pure request-mutation path preserves TLS state and protocol streaming.
- Optional-log-integration spike: implement and validate the §8 parser recipe only when that
  integration is requested. It does not gate core Realclient v1. Feed forged public/private XFF
  and X-Real-Ip through covered, unmatched, 400/421 and abnormal paths; inspect source_ip,
  whitelist state, GeoIP metadata and resulting decisions, not just parser syntax.
  Include an acquired but uncovered internal router with forged identity, missing entrypoint
  metadata, and covered internal routers; verify the entrypoint field's exact serialized name.

### V1 — generic best-effort resolver

Deliver ordered first-success sources, the four trust predicates in §3.4, single-IP extraction,
source scheme extraction (single/uniform-list), pure-data presets, strict configuration,
canonical normalization, shared feed workers, optional transactional disk cache, and useful
feed diagnostics. Document deployment input preservation and downstream request-time consumers.
No synchronous network startup dependency; no response marker; no HTTP rejection policy for
ordinary failed resolution; no account credentials.

Native unit and integration tests must cover:

- No sources; all predicates standing alone; static/feed union; overlapping sources; first
  source predicate failure and extraction failure followed by later success; every source fails.
- Private/internal identities; IPv4/IPv6, mapped prefixes and addresses, zones, /0 by family,
  malformed ports, bracketed peer IPv6, forbidden identity forms, duplicate header instances.
- Header-role precedence and deletion across unselected sources; case/underscore aliases;
  preservation of country/provider metadata; canonical direct and resolved RemoteAddr tuples.
  Confirm Traefik's delete alias posture blocks dotted aliases; document the unsupported keep
  posture with a backend that maps punctuation to CGI-style names. Duplicate extraction-header
  tests use X-Real-Ip/custom inputs; separate tests assert Traefik's XFF instance joining.
- Exact identifiers without numeric coercion; actual wire whitespace handling; hostname label
  boundaries, trailing dot plus port, invalid ports/IDNs/IP literals, duplicate host predicates.
- Scheme independent of IP: TLS and non-TLS origin crossed with HTTP and HTTPS original scheme;
  absent/invalid/duplicate/mixed/uniform-list metadata; actual WebSocket versus other upgrades.
- Feed body limits, trailing garbage, duplicate-normalized counts, private CIDRs, invalid entry
  among valid ones, valid and invalid cache, 200/304, ETag changes only after validation,
  timeout/TLS/error responses, atomic cache interruption and failed persistence.
  Use a controlled HTTP server for conditional requests. A below-minimum response retains old
  LKG/cache and the other family; test initial empty state separately. Preset minima accept
  legitimate consolidation down to one entry.
- One feed loaded while the other is empty/LKG; static membership during outages; later updates
  learning new edges. Readers see complete per-feed snapshots, not a promised whole-source epoch.
- Concurrent New calls and asynchronous cache loading, including blocked cache I/O that does
  not block construction; identical reloads reuse workers; changed
  policy/URL/cacheDir creates independent workers; canceled router contexts do not stop polling;
  removed sources cease participating. Measure workers for stable keys, not all process goroutines.
- Real CrowdSec bouncer and AppSec: ban a resolved test client, allow another, and verify fallback
  requests use the peer. Repeat with IPv6 and mapped representations where the harness permits.
- Badger configured as documented; mtlswhitelist certificate path and separate no-certificate
  IP-range path; downstream passTLSClientCert clears forged input and uses real certificates.
- Backend-observed XFF, X-Real-Ip and scheme; WebSocket handshake/data, native HTTP/2 and gRPC
  streaming through the intended full chain. Do not promise that AppSec inspects every message.
  Compare forwarding outputs with stock Traefik: consistent scheme aliases, preserved server
  identifier, original HTTP over TLS-origin port behavior, and delegated XFCC preservation.

Run native race tests for registries/snapshot publication and actual Yaegi integration tests:
native compilation alone is not Yaegi compatibility proof. Pin the supported Traefik release,
its bundled Yaegi and Go toolchain in test documentation; master source inspection is not a
blanket compatibility guarantee for older releases.
The bundled interpreter's supported constructs and exported symbols are the API contract, not
Traefik's newer build toolchain. The inspected Yaegi tables expose a Go 1.22-era surface, but that
does not promise support for all Go 1.22 language features. Avoid newer exports such as
strings.SplitSeq. Use a minimum-toolchain build and/or explicit `go vet` stdversion analysis in
addition to Yaegi tests; a go.mod language directive or -lang flag alone does not restrict newer
standard-library APIs supplied by a newer compiler.

### V1.1 — optional additions, separately justified

- `trust.headerEquals` backed by `valueFrom: file:`, constant-time comparison and guaranteed
  secret deletion after all source attempts. Load files at construction; rotation requires
  reload. Secret deletion takes precedence over metadata preservation; reject secrets sharing
  identity/scheme output names. Do not mutate shared preset data or log secret values.
- Optional strict policy, only if needed: after all sources fail, reject only if at least one
  source fully matched its trust predicates but could not extract identity. Predicate non-matches
  alone remain fallback, later successes always win, and synthesized managed headers remain
  indistinguishable. This is not required-account authentication.
- Periodic counters if operational experience warrants them.

### Later, only on concrete demand

XFF rightmost-untrusted extraction with an explicit inner-proxy model; RFC 7239 parsing;
additional original host/port metadata; provider-account inventory with appropriately scoped
credentials; stale-age/shrink policies; worker reclamation if real configuration churn needs it.
No provider-inventory framework, boolean policy DSL, HMAC protocol, or custom proxy is prebuilt.
Original-scheme support is already v1, not deferred here.

## Appendix A. Evidence retained and corrected

### A.1 Upstream source evidence

Traefik was independently inspected at
[`d48621ce0b6fd221b20bdb6c22e652e7498e5db6`](https://github.com/traefik/traefik/tree/d48621ce0b6fd221b20bdb6c22e652e7498e5db6).
Other references below state their inspected revision; moving links are evidence dated
2026-09-07/08 and must be pinned in implementation fixtures.

| Reference | Verified finding and consequence |
|---|---|
| [Forwarded headers](https://github.com/traefik/traefik/blob/d48621ce0b6fd221b20bdb6c22e652e7498e5db6/pkg/middlewares/forwardedheaders/forwarded_header.go) | Secure mode strips managed headers for untrusted peers. Both modes fill empty X-Real-Ip and XFP. Non-managed headers are not stripped by that trust check, but Connection-nominated headers can still be removed before plugins. Old “never touched” language was too broad. |
| [Entrypoint model](https://github.com/traefik/traefik/blob/d48621ce0b6fd221b20bdb6c22e652e7498e5db6/pkg/server/aggregator.go) and [router chain](https://github.com/traefik/traefik/blob/d48621ce0b6fd221b20bdb6c22e652e7498e5db6/pkg/server/router/router.go) | Defaults attach to roots; parent middleware wraps child muxers. Unmatched entrypoint requests use the default observability/404 handler. RouterName is set before user middleware; it is not proof of execution. |
| [SNI check](https://github.com/traefik/traefik/blob/d48621ce0b6fd221b20bdb6c22e652e7498e5db6/pkg/middlewares/snicheck/snicheck.go), [encoded-path denial](https://github.com/traefik/traefik/blob/d48621ce0b6fd221b20bdb6c22e652e7498e5db6/pkg/server/router/deny.go), [recursion guard](https://github.com/traefik/traefik/blob/d48621ce0b6fd221b20bdb6c22e652e7498e5db6/pkg/middlewares/denyrouterrecursion/deny_router_recursion.go) | Ordinary router checks can stop before Realclient with 421 or 400. These findings motivate exclusions only in the optional log recipe. |
| [Access logger](https://github.com/traefik/traefik/blob/d48621ce0b6fd221b20bdb6c22e652e7498e5db6/pkg/middlewares/accesslog/logger.go) | ClientAddr/ClientHost are copied before middleware; ClientHost may come from XFF. Request.headers retains the original map and is serialized later. Retained canonical request headers are loggable after in-place mutation. |
| [HTTP proxy](https://github.com/traefik/traefik/blob/d48621ce0b6fd221b20bdb6c22e652e7498e5db6/pkg/proxy/httputil/proxy.go) | Normal backend XFF append takes the host from RemoteAddr. The notAppendXFF option and downstream header mutations qualify any single-entry claim. |
| [Plugin builder](https://github.com/traefik/traefik/blob/d48621ce0b6fd221b20bdb6c22e652e7498e5db6/pkg/plugins/builder.go), [Yaegi adapter](https://github.com/traefik/traefik/blob/d48621ce0b6fd221b20bdb6c22e652e7498e5db6/pkg/plugins/middlewareyaegi.go), [router factory](https://github.com/traefik/traefik/blob/d48621ce0b6fd221b20bdb6c22e652e7498e5db6/pkg/server/routerfactory.go) | Interpreter per configured plugin alias; handler construction repeats on rebuild. There is no explicit Close method, but router contexts are canceled on reload. Weak mapstructure decoding needs a strict plugin-owned boundary. |
| [Yaegi netip exports](https://github.com/traefik/yaegi/blob/v0.16.1/stdlib/go1_22_net_netip.go), [atomic exports](https://github.com/traefik/yaegi/blob/v0.16.1/stdlib/go1_22_sync_atomic.go) | The inspected bundled Yaegi version exposes netip and atomic.Value. Runtime validation of the actual constructs remains necessary. |
| [CrowdSec IP handling](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/04d9288/pkg/ip/ip.go), [bouncer/AppSec](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/04d9288/bouncer.go) | Default empty trusted pool selects the rightmost nonempty XFF value, otherwise SplitHostPort(RemoteAddr). More generally it also falls back if all header addresses are trusted. Parsing failure invokes technical rejection, not necessarily creation of a persistent ban decision. AppSec uses the same resolved IP. |
| [Badger](https://github.com/fosrl/badger/blob/926d126/main.go) | Default CF ranges affect both getRealIP and setIPHeaders. Clear conflicting CF identity/scheme headers and disable its independent trust interpretation for the documented integration. |
| [mtlswhitelist IP rule](https://github.com/smerschjohann/mtlswhitelist/blob/main/iprange.go), [handler](https://github.com/smerschjohann/mtlswhitelist/blob/main/mtlsOrWhitelist.go), [Traefik certificate headers](https://github.com/traefik/traefik/blob/d48621ce0b6fd221b20bdb6c22e652e7498e5db6/pkg/middlewares/passtlsclientcert/pass_tls_client_cert.go) | IP rules read X-Real-Ip then XFF. The certificate path reads PeerCertificates and branches before whitelist evaluation. The downstream Traefik producer can regenerate certificate headers from TLS state. |
| [Stock CrowdSec Traefik parser](https://github.com/crowdsecurity/hub/blob/master/parsers/s01-parse/crowdsecurity/traefik-logs.yaml), [ordering](https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/parser/unix_parser.go), [runtime](https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/parser/runtime.go) | Stock source_ip comes from the rightmost ClientHost value; IPv6 ClientAddr splitting is unsuitable. Attribution must precede enrichment/whitelisting. Parser order and next_stage affect which processing runs. |
| [Cloudflare headers](https://developers.cloudflare.com/fundamentals/reference/http-headers/) | Original XFP is documented; Pseudo IPv4 overwrite and Worker subrequests qualify CF-Connecting-IP semantics. CF-IPCountry is metadata, not another client IP. |
| [Go netip](https://github.com/golang/go/blob/master/src/net/netip/netip.go), [HTTP/1 header reader](https://github.com/golang/go/blob/master/src/net/textproto/reader.go) | Address family, mapped-prefix and zone handling must be explicit; ParsePrefix does not mask host bits. Middleware sees parsed header values, not preserved wire whitespace. |

Valid host:port, rather than port zero specifically, is the downstream requirement. Previous
execution checked SplitHostPort on IPv4 :0 and bracketed IPv6 :0; the inspected consumers discard
or string-handle the port. This is retained as compatibility evidence, not a fresh runtime test.

### A.2 Previously measured Bunny behavior

These observations are carried forward from the original design's Edge Script echo app and
disposable Pull Zone experiments. This revision did not repeat them.

1. With no Edge Rules, origin X-Real-IP and XFF each contained the real client IP. XFF was not
   "CDN IP, client IP". Supplied spoof values and duplicate X-Real-IP instances were overwritten.
2. A Pull Zone owner could customize X-Real-IP/XFF using Edge Rules or Scripting. Provider-level
   trust is therefore not account binding, even though ordinary clients on the tested stock
   path could not spoof those IP headers.
3. Edge Rules refused to set CDN-PullZoneId with the message that CDN-prefixed headers are not
   allowed. Scripted identity changes still left genuine CDN metadata in the observed origin
   request. Direct requests to Traefik can nevertheless supply arbitrary CDN metadata.
4. The same zone reached through test-pabb4.b-cdn.net, test-pabb4.bunny.run and btest.oandc.fun
   produced those respective CDN-Host values. An unrelated unconfigured Host was rejected by
   Bunny rather than reaching the origin.
5. Adding an unowned custom hostname succeeded without DNS ownership verification and routed
   immediately. Re-registering an already attached exact hostname on another zone was rejected.
   This supports exact-name uniqueness, not ownership of every name under a suffix.
6. Still untested: whether CDN-Host changes with an origin Host override or a rule changing Host.
   This limits the account-binding interpretation of hostExact, not generic exact comparison.
7. One capture with rules/scripting active produced XFP `https, https` despite no supplied XFP.
   Cause and authority were not established. Uniform-list parsing accepts agreement without
   inventing a hop topology; source provenance remains a separate requirement.
8. Observed non-IP metadata included CDN-ConnectionId, CDN-RequestId, CDN-JA4, CDN-LoopCount,
   CDN-ProxyVer, CDN-MobileDevice, CDN-ServerZone and CDN-RequestStateCode, as well as CDN-Host,
   CDN-PullZoneId, CDN-RequestCountryCode and CDN-ServerId.

Feed probes recorded on 2026-09-07:

| Feed | Observed representation |
|---|---|
| Bunny /system/edgeserverlist/plain | 586 individual IPv4 addresses, line format, ETag. |
| Bunny /system/edgeserverlist/ipv6 | Approximately 300 individual IPv6 addresses, JSON array, including with ?plain=true. |
| Cloudflare /ips-v4 | 15 CIDRs. |
| Cloudflare /ips-v6 | 7 CIDRs. |

These are measurements, not permanent counts, prefix floors, or a guarantee that feeds never
change. Generic feeds are not required to resemble either provider.

## Appendix B. Adversarial review disposition

Numbers refer to the original independent review. Appendix C records the subsequent Claude
review and counter-review; its decisions supersede earlier dispositions where explicitly changed.

| Finding | Disposition and reason |
|---|---|
| 1. Header presence is not execution proof | **Accepted; remedy changed.** Remove the old three-way classifier. Optional log integration uses explicit coverage and conservative early-status exclusions; no core marker mechanism. |
| 2. Traefik synthesizes missing Bunny identity | **Accepted; policy changed.** Equal-to-peer identity is valid best effort, not an HTTP error. Document inability to distinguish synthesis. |
| 3. Overlapping sources conflict | **Accepted.** First full predicate match plus successful extraction wins; every failure permits later sources. |
| 4. Decoder and preset hardening loss | **Accepted.** Strict raw boundary, limited explicit overlay, whole-list replacement, explicit duration parsing and unsupported-field errors. |
| 5. Worker policy/lifecycle ambiguity | **Accepted; simplified.** Immutable full-spec keys, per-interpreter sharing and intentional background lifetime. No live policy merging or refcounting. |
| 6. Late CrowdSec override | **Accepted for optional integration.** One replacement s01 parser attributes before s02; no after-the-fact source_ip patch. |
| 7. Partial feeds/POP attribution | **Accepted as inherent information loss.** Use available unions and peer fallback; readiness denial and a mandatory CDN whitelist are rejected as core requirements. |
| 8. Scheme is not origin TLS | **Accepted in v1.** Trusted source metadata with single/uniform-list parsing; transport is the explicit fallback. |
| 9. IP normalization gaps | **Accepted; restrictions reduced.** Canonical direct host/port and explicit prefix-family rules; legitimate private/local client identities remain supported. |
| 10. Overfit feed guards | **Accepted.** Remove public-space and prefix-floor assumptions; retain strict complete parsing, resource limits, distinct minimum counts and LKG. |
| 11. Cache/ETag transaction | **Accepted.** Validated representation and validator stay together; revalidate cache and atomically replace files. |
| 12. Cloudflare exceptions | **Accepted.** Document supported settings/Worker limitations rather than adding provider-specific extraction. |
| 13. Child/root ordering | **Accepted.** Correct inherited execution and document root-routing visibility. |
| 14. Parsed header/hostname semantics | **Accepted.** Parsed-value comparisons, explicit DNS grammar/order, cardinality and header-role precedence. |
| 15. Earlier falsification tests | **Accepted with scope change.** Core runtime/config/order spikes are v0; optional CrowdSec parser validation gates only that integration. |
| Optional setRealIP switch | **Accepted.** Remove it: every usable request receives the canonical effective identity. |
| Optional metadata consistency | **Accepted.** Preserve CF-IPCountry alongside Bunny country metadata; remove Cf-Visitor because it competes on scheme. |
| Optional Bunny suffix blacklist | **Accepted.** Generic matching has no provider-domain blacklist; document provenance and namespace limits. |
| Response marker/execution-proof architecture | **Deferred unless an integration demands broader coverage.** Not needed for resolution or the conservative optional log recipe; full transparent log attribution is not promised. |
| Default strict HTTP rejection/account authentication | **Rejected as the project baseline.** Resolution failure is peer fallback; authorization belongs elsewhere. Limited strict extraction policy and secrets remain optional later work. |

The architecture can proceed to the v0 checks without treating optional log detection or Bunny
account binding as prerequisites. Implementation starts only under a separate implementation task.

## Appendix C. Claude review and counter-review disposition

This follow-up incorporates the agreed corrections without changing the best-effort resolver
architecture. Numbers below refer to Claude's 30-point review. Source checks support the
corrections; planned integration behavior still requires §9's runtime tests.

| Finding | Disposition and reason |
|---|---|
| 1. Connection-nominated deletion | **Accepted.** §2.2 specifies preservation requirements and externally induced source reselection; test allowlisted and unprotected inputs. |
| 2. Shared decoded config | **Accepted.** §3.3 requires read-only input and independent internal settings; test repeated/concurrent router construction without mutation. |
| 3. Parseable prohibited peers | **Accepted with corrected evidence.** Separate peer fallback from extracted-identity restrictions. PROXY LOCAL retains the real peer; it is not the advertised-zero-address case. |
| 4. Synthesized identity pre-emption | **Accepted as an ordering warning.** Keep first-success selection. Supplied invalid values can still fail; scheme does not select IP sources. Reject special equal-to-peer continuation, which could override a legitimate preferred source. |
| 5. Log coverage discriminator | **Accepted with qualification.** Explicit covered entrypoints supplement RouterName and exclusions. Internal routers are included. Entrypoint identity alone is not execution proof. |
| 6. Clearing feeds removes anchoring | **Accepted as guidance/diagnostics.** Warn for effective header-only trust; no mandatory acknowledgement flag or peer anchor. |
| 7. Provider count floors | **Accepted; failure account corrected.** Presets use minimum one. Rejected updates retain existing valid LKG/cache and do not invalidate independent feeds. A minimum of five accepts five. |
| 8. Conditional-request evidence | **Clarified.** Observing an ETag did not prove 304 support. Claude reported conditional requests returning 200; that probe was not repeated here and does not replace retained measurements. Keep generic ETag support and controlled-server tests. |
| 9. Cache trust boundary | **Accepted.** Protect cache files, directory and parent path from untrusted writers; cache syntax validation does not authenticate provenance. |
| 10. Blocking cache initialization | **Accepted as a tradeoff.** Load in the worker, remove construction waiters, and explicitly accept fallback while a valid cache is still loading. |
| 11. Partial feeds select later sources | **Already covered.** §6.4 explicitly tries other sources before peer fallback; no new selection rule. |
| 12. Cold-start POP attribution | **Clarified.** Connect startup fallback to downstream enforcement/detection. No mandatory seeds or bouncer bypass; bouncer presence alone does not generate persistent bans. |
| 13. Other upstream rewrites | **Accepted.** Document synthesis, WebSocket tokens and XFF joining; use observable inputs in cardinality tests. |
| 14. Scheme aliases | **Accepted.** Publish both aliases consistently with canonical XFP rather than disabling consumers of those headers. |
| 15. Additional identity channels | **Partially accepted.** Add the three IP headers. Preserve delegated XFCC by default: certificate-assertion policy is outside generic IP normalization. |
| 16. Yaegi API limits | **Accepted; CI remedy corrected.** Actual exported symbols/language support govern compatibility. A language-version flag alone does not limit newer stdlib APIs; retain interpreter tests plus minimum-toolchain/stdversion checks. |
| 17. Label/KV decoding | **Accepted as a contract gap.** Define field-specific decimal integer strings, preserve list/identifier strictness and verify provider syntax in V0. Do not claim all label/KV configurations are necessarily unsupported. |
| 18. Cloudflare scheme evidence | **Rejected.** The provider explicitly documents overwriting client XFP. Keep the default and the existing input-preservation caveat; live measurement is corroboration, not required to accept the published contract. |
| 19. Authority parsers | **Accepted as simplification.** Share splitting, retain distinct hostname versus forwarding-output validation. Different acceptance policies were not themselves a bug. |
| 20. Falsification tests | **Accepted with corrected expectations.** Add shared-input, Connection, ordering, PROXY, coverage and backend tests. Assert retained LKG and the documented alias posture, not the review's incorrect failure expectations. |
| 21. X-Forwarded-Server | **Accepted.** Preserve Traefik's synthesized value except when consumed as an explicit input. |
| 22. Retry jitter | **Accepted.** Apply the same small jitter to failures; no backoff framework. |
| 23. User-Agent | **Accepted as operational courtesy.** Identify the plugin without claiming a custom UA prevents provider filtering or relying on the review's Go-default-UA claim. |
| 24. Duplicate execution | **Clarified.** Document scheme loss and possible further identity changes; no promise of idempotence. |
| 25. Forwarded port | **Clarified with corrected evidence.** Traefik already considers XFP. Document the specific original-HTTP/TLS-origin difference instead of claiming it uses only origin transport. |
| 26. Extended CONNECT | **Clarified.** Only the specified Upgrade handshake gets ws/wss output; other transports retain HTTP/HTTPS without inferring protocol state. |
| 27. Reserved input headers | **Accepted.** Enumerate connection/framing exclusions. |
| 28. Response writer | **Rejected.** Writing an error response does not replace or wrap the response writer. |
| 29. Release wording | **Partially accepted.** Move secret precedence to v1.1. Original-host recovery differs from current-authority output; future strict policy does not require v1 to retain unused failure state. |
| 30. Internal routers | **Accepted.** Explicitly document default-middleware application and construction-failure effects. |

Additional evidence checked during the counter-review:

- [Pinned mapstructure interface decoding](https://github.com/mitchellh/mapstructure/blob/8508981c8b6c/mapstructure.go)
  assigns reference-bearing values without recursively cloning them.
- [PROXY protocol RemoteAddr](https://github.com/pires/go-proxyproto/blob/v0.12.0/protocol.go)
  uses the underlying connection for LOCAL, and advertised source information for PROXY.
- [Entrypoint observability](https://github.com/traefik/traefik/blob/d48621ce0b6fd221b20bdb6c22e652e7498e5db6/pkg/server/middleware/observability.go)
  adds entrypoint metadata; runtime log fixtures must verify its serialized name and coverage.
- [Cloudflare's XFP contract](https://developers.cloudflare.com/fundamentals/reference/http-headers/#x-forwarded-proto)
  explicitly states overwrite behavior; the same page documents Connection normalization.
- [Yaegi strings exports](https://github.com/traefik/yaegi/blob/v0.16.1/stdlib/go1_22_strings.go)
  lack SplitSeq; [stdversion analysis](https://pkg.go.dev/golang.org/x/tools/go/analysis/passes/stdversion)
  detects references to stdlib symbols newer than the configured Go version.

Mixed scheme metadata falling back to origin transport is not a security guarantee: HTTPS client
traffic over plaintext origin transport becomes HTTP on fallback. §4.3 makes that limitation explicit.
The resulting plan is ready for V0 feasibility checks; optional log integration still has its own gate.
