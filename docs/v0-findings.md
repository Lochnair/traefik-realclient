# V0 configuration findings — blocker resolved after review

Date: 2026-09-08. Design baseline: `bed30f281a6cd8d6150f474b2d7878c7a233a868`.
**Current outcome: configuration blocker resolved by the reviewed typed decoded-value
contract; [remaining core V0 probes completed](v0-core-findings.md). V1 remains
unimplemented pending review.**

The raw-map contradiction and initial stop recorded below are historical evidence.
No V1 resolver, feed implementation, or optional CrowdSec parser was added.

## Runtime and reproduction

- Official Traefik **3.7.12**, darwin/arm64, built 2026-08-26T13:34:13Z with
  **Go 1.26.7**; bundled **Yaegi 0.16.1**.
- Archive `traefik_v3.7.12_darwin_arm64.tar.gz` SHA-256:
  `bb71997e9b2b3215f2a518d08a6689eba94252ca8d0376f68e11504518dd46f4`,
  matched against the official release checksum file.
- Local formatting tool: Go 1.27.0. No minimum-toolchain or race-test result is
  claimed. No support claim is made for other releases or providers.
- Sources: [official release](https://github.com/traefik/traefik/releases/tag/v3.7.12),
  [dependency pins](https://github.com/traefik/traefik/blob/v3.7.12/go.mod),
  [actual adapter](https://github.com/traefik/traefik/blob/v3.7.12/pkg/plugins/middlewareyaegi.go).

From the repository root, with Python 3 and that verified binary:

```sh
python3 tests/v0/raw_boundary.py --traefik /absolute/path/to/traefik --output /tmp/realclient-v0-results
```

The harness uses a temporary local-plugin directory, a loopback-only ephemeral
listener, and Traefik's real file provider and Yaegi adapter. Its generated JSON
configuration is valid YAML, loaded through `providers.file.filename` as `.yml`.
The probe returns a JSON snapshot of the raw map received by `New`; it does not
validate, overlay, resolve, forward, or start workers. The unused backend address
is never called. The harness shuts down its own Traefik process and exits **1**
on the first mismatch. Expected output for this pinned runtime:

```text
CONTRADICTION nested
```

Checked-in evidence: [received versus supplied config](../tests/v0/evidence/boundary.json)
and [runtime log](../tests/v0/evidence/traefik.log). The log contains disposable
local paths and synthetic inputs, not production configuration.

## Blocking finding: empty overlays lose their shape

The first fixture contains a nonempty ordered source/feed list, decimal
`minEntries: "1"`, `refreshInterval: "1s"`, `trust.static: []`, and `scheme: {}`.
The plugin loaded successfully through Yaegi and returned HTTP 200. Nonempty
nested lists and their string fields reached `New`. However:

| Supplied field | Value received by the raw-map plugin |
|---|---|
| `sources[0].trust.static: []` | `""` |
| `sources[0].scheme: {}` | `""` |

This contradicts §3.2's supported empty-list replacement and empty-object scheme
disabling syntax, combined with §3.3's strict shape checking. A strict validator
would reject these documented configurations. Accepting `""` as either shape
would silently relax the contract and conflate a supplied string with an empty
collection. No such workaround is implemented.

The `Configuration received` log from the file provider already contains these
strings. This localizes the observed loss to before the plugin's `New`; it is
not caused by the probe's JSON serialization or an in-place preset overlay.
Changing only the plugin's raw-map adapter cannot reconstruct the lost shapes.

The same provider event also shows `sources: []` becoming `""`, explicit null
fields disappearing, and numeric/boolean scalars becoming strings. These are
observations from the already-loaded fixture set, **not subsequent completed
HTTP assertions**: execution stopped on the first nested-config mismatch.
Null disappearance conflicts with enforcing “explicit null values are invalid
everywhere”; a plugin cannot distinguish omitted fields from these removed nulls.
Scalar conversion is subject to §3.3's existing provider-conversion caveat and
is not independently presented as a newly falsified promise.

Review must decide the supported external representations and where strict
validation can actually occur. Empty-overlay and null semantics need an explicit
contract decision before further implementation. No replacement is selected here.

## Coverage at the stop point

- Demonstrated: minimal raw-map plugin loading through the actual file provider,
  Traefik adapter and Yaegi; observation of a nested source/feed list and the
  blocking empty-overlay transformation.
- Not completed: strict recursive validation, duration/integer rejection, preset
  overlay, label/KV provider syntax, repeated/concurrent construction and shared
  input comparisons, netip keys, atomic.Value, goroutines and registry primitives.
- Not started: secure/insecure header handling, synthesized headers and source
  ordering, Connection nominations, placement/child and unmatched 404 coverage,
  SNI/encoded-path rejection, PROXY versus LOCAL, access-log fields/buffering,
  TLS-state preservation and protocol streaming.
- Optional CrowdSec log-parser spike: excluded as requested.

These unexecuted checks are not passes. Review this finding before resuming V0;
review the eventual V0 results before authorizing V1.

## Reviewed resolution — 2026-09-08

The follow-up [typed-adapter spike](v0-typed-adapter-findings.md) completed 23
observations. Recursive `,remain` maps retain tested unknown keys, typed slices
reconstruct empty lists (conflating `[]` with `""`), empty objects fail before
`New`, and null equals omission. These results resolve the configuration blocker
by changing the external contract, not the Realclient architecture.

The reviewed §3 contract now uses typed borrowed/read-only config, independent
internal settings, strict validation over decoded values, omission semantics for
null, invalid supplied empty lists, and monotonic preset-member overlay without
clearing operations. The earlier stop statements above describe the historical
stop point. Core V0 may now continue; V1 still requires review of the V0 findings.
