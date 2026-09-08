# V0 feasibility probes

These are disposable probes, not the Realclient V1 implementation. Start with
[core findings, tested syntax and reproduction](../../docs/v0-core-findings.md).

| Harness | Purpose |
|---|---|
| `config.py` / `config-plugin/` | Selected decoded validation and synthetic preset overlay |
| `primitives.py` / `primitives-plugin/` | Actual interpreted concurrent New calls, read-only input, independent copies, registry and atomic/netip primitives |
| `providers.py` | Actual scoped Docker labels and Redis KV through `config-plugin/` |
| `runtime.py` / `runtime-plugin/` | Header boundary, ordering, routing, PROXY, TLS, streaming and buffered access logs |
| `boundary.py` / `plugin/` | Historical 23-case typed adapter observation |
| `raw_boundary.py` / `raw-plugin/` | Historical raw-map reproducer; intentionally stops on its first mismatch |

All use pinned Traefik 3.7.12 / Yaegi 0.16.1. The core harnesses assert their
observed contracts and stop on failures. The historical typed observer's exit 0
only means observation completed. Tests/evidence are separate from V1, which
still awaits review. No optional CrowdSec parser is present.

Do not deploy these plugins: some return configuration to callers, and the
request fixture implements only a deliberately narrow synthetic selection rule.
Its `X-V0-*` observation headers are test instrumentation, not product features.
