# Typed configuration-adapter V0 spike

2026-09-08. **Historical result: option 2 for the then-current strict configuration contract.**
The tested file-provider boundary remains too lossy with typed targets, although
`,remain` successfully captures the tested unknown fields. This is a configuration
contract limitation, not a falsification of the Realclient architecture.

At this historical stop point, only this additional adapter spike was run. The design contract was not changed;
V1 and all remaining V0 runtime checks remain paused. No workaround was added.

## Runtime and method

Same verified official Traefik **3.7.12**, darwin/arm64, built with **Go 1.26.7**,
and bundled **Yaegi 0.16.1** as the [first spike](v0-findings.md).
The actual file provider loads JSON-form YAML from a `.yml` file and constructs
the local plugin through Traefik's existing decoder. No substitute decoder,
decode hook, provider, or resolver was implemented.

[Typed probe](../tests/v0/plugin/probe.go) returns `*Config` from `CreateConfig`.
It uses `[]Source`, pointers to optional structs, `*[]string` and `*[]Feed`, and
pointer strings. Every struct has `map[string]interface{}` (the same type as
`map[string]any`) tagged `mapstructure:",remain"`. There are no defaults.
`New` only marshals and observes configuration; it does not mutate decoded data.
JSON uses no `omitempty`; supplementary `V0_SHAPES` log records distinguish nil
pointers from pointers to nil/non-nil slices. This is not a full schema validator.

```sh
python3 tests/v0/boundary.py --traefik /absolute/path/to/traefik --output /tmp/realclient-v0-typed-results
```

The harness completes all 23 observations, including decoding failures, and exits
0 when observation completes; that exit code does **not** mean the contract passed.
Nineteen cases reached `New`; four failed decoding before construction. Each
successful response was cross-checked against its `V0_NEW` log snapshot; each
failure against the adapter error and absence of a constructor marker. A repeat
with added nil-shape diagnostics produced the same HTTP/configuration outcomes.

Exact inputs and complete `New` snapshots, including every null/default field:
[boundary.json](../tests/v0/evidence/typed/boundary.json),
[supplied.json](../tests/v0/evidence/typed/supplied.json), and
[Traefik log](../tests/v0/evidence/typed/traefik.log).

## Container and presence results

Every source has `name: probe`. “Omitted” below means the field is absent; the
`static-omitted` control includes a nonempty feed so the containing trust object
survives the provider. `trust: {}` omits its predicates, not the trust object.

| Case/input | What `New` receives, or why it is not called |
|---|---|
| Trust and scheme omitted | `Trust == nil`, `Scheme == nil` |
| `trust: {}` | **Not called**: `'Sources[0].Trust' expected a map, got 'string'` |
| Static omitted within nonempty trust | Non-nil `Trust`, `Static == nil` |
| `trust.static: []` | Non-nil `Trust`, non-nil `Static` pointer to a non-nil empty `[]string` |
| `trust.static: ""` (wrong scalar type) | **Exactly the same decoded configuration as `static: []`** |
| `trust.static: null` as the only trust field | **Not called**: `'Sources[0].Trust' expected a map, got 'string'`; null disappears and the emptied parent becomes `""` |
| `trust.static: ["192.0.2.0/24"]` | Pointer to non-nil one-element `[]string` with that value |
| `trust.feeds: []` | Non-nil `Feeds` pointer to non-nil empty `[]Feed` |
| `sources: []` | Non-nil empty `[]Source` |
| Sources omitted (`feedCacheDir: /unused`) | Nil `[]Source`; cache-directory pointer contains `/unused` |
| `scheme: {}` | **Not called**: `'Sources[0].Scheme' expected a map, got 'string'` |
| `scheme: null` | `Scheme == nil`; complete decoded configuration equals the omitted baseline |
| `scheme: ""` | **Not called**, same adapter error as `scheme: {}` |
| Nonempty scheme with header/mode strings | Non-nil scheme pointer with those exact strings and nil remain map |

All pre-construction failures produced an uninstalled route and HTTP 404 in this
harness, rather than a plugin response. The adapter errors, not HTTP 404 alone,
are the evidence of construction failure.

The provider log shows empty collections becoming `""` before typed decoding.
Typed slices reconstruct empty lists, but cannot recover whether the supplied
value was a list or a string. Pointer-to-struct fields do not reconstruct empty
objects from that string. **Explicit-null distinction is not recoverable** on
this path; no sentinel, default trick, or coercion is proposed.

## Unknown-field results

All nine unknown-field cases reached `New`. Each field below appears in the
`Unknown` map on the corresponding typed struct, with its original tested spelling.
Known fields still decoded into their typed destinations.

| Struct/location | Captured remain entry |
|---|---|
| Config | `unexpectedTop: {value: "kept"}` |
| Source | `unexpectedSource: "kept"` |
| Trust | `unexpectedTrust: "kept"` |
| Feed list element | `unexpectedFeed: "kept"` |
| Extraction | `unexpectedExtract: "kept"` |
| Scheme (same struct type as extraction) | `unexpectedScheme: "kept"` |
| HeaderIn | `unexpectedHeaderIn: "kept"` |
| HostExact | `unexpectedHostExact: "kept"` |
| HostSuffixes | `unexpectedHostSuffixes: "kept"` |

Thus `,remain` works for these surviving unknown keys through the real adapter
and Yaegi. This does not establish preservation of unknown null fields, original
scalar types, or exact-case validation of known fields. No label/KV provider
support is inferred from this file-provider result.

## Stop point

Typed targets improve unknown-key capture and distinguish omitted lists from
explicit empty lists in the tested controls. They do **not** preserve the full
required container/type semantics: `[]` and `""` collide, `{}` fails for optional
structs, and null equals omission. The current strict contract remains blocked
at the configuration boundary. Review these findings before deciding any design
changes. No further V0 or V1 work was performed.

## Subsequent review decision — 2026-09-08

The user accepted a revised decoded-value contract and authorized remaining core
V0 work. The earlier conclusion applies to the old contract. The revised §3 uses
typed structs with recursive `,remain`, null-as-omission, invalid supplied empty
lists, and no preset-clearing syntax. This resolves the configuration blocker;
it does not authorize V1 implementation.
