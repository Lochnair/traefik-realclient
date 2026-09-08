#!/usr/bin/env python3
"""Run the whole V1 Traefik-runtime integration suite.

  python3 tests/v1/run.py --traefik "$(which traefik)" --output /tmp/v1

Suites tagged `docker` need Docker + network (CrowdSec images, third-party
plugin source). `--skip` omits suites by name.
"""
import argparse
import importlib
import pathlib
import sys
import time

SUITES = [
    ("core", set()),
    ("streaming", set()),
    ("certs", {"network"}),
    ("crowdsec", {"docker", "network"}),
    ("appsec", {"docker", "network"}),
    ("badger", {"network"}),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--traefik", required=True)
    ap.add_argument("--output", type=pathlib.Path, required=True)
    ap.add_argument("--skip", nargs="*", default=[])
    a = ap.parse_args()
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    binary = str(pathlib.Path(a.traefik).resolve())
    a.output.mkdir(parents=True, exist_ok=True)

    summary = []
    for name, _tags in SUITES:
        if name in a.skip:
            summary.append((name, "skipped"))
            continue
        print(f"\n{'=' * 20} {name} {'=' * 20}", flush=True)
        mod = importlib.import_module(name)
        start = time.monotonic()
        try:
            rc = mod.run(binary, (a.output / name).resolve())
        except Exception as exc:  # noqa: BLE001
            print(f"!! {name} crashed: {exc}", flush=True)
            rc = 2
        summary.append((name, ("ok" if rc == 0 else "FAIL") + f" ({time.monotonic() - start:.0f}s)"))

    print("\n" + "=" * 50)
    for name, status in summary:
        print(f"  {name:12s} {status}")
    return 0 if all("FAIL" not in s for _, s in summary) else 1


if __name__ == "__main__":
    raise SystemExit(main())
