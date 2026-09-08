#!/usr/bin/env python3
"""Stop at the first raw-config contract contradiction. No V1 behavior."""
import argparse
import json
import pathlib
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def run(binary, output):
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="realclient-v0-") as temp:
        root = pathlib.Path(temp)
        plugin = root / "plugins-local/src/example.com/realclientv0"
        shutil.copytree(pathlib.Path(__file__).parent / "raw-plugin", plugin)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        # JSON is valid YAML; this keeps scalar types and expected data explicit.
        cases = {
            "nested": {"sources": [{"name": "probe", "trust": {"static": [], "feeds": [{"url": "https://example.invalid/feed", "minEntries": "1", "refreshInterval": "1s"}]}, "extract": {"header": "X-Real-Ip", "mode": "single"}, "scheme": {}}]},
            "unknown": {"headerEquals": {"value": "retained"}, "sources": []},
            "scalars": {"identifier": 6498612, "boolean": True, "duration": 12, "fraction": 1.5, "list": ["a", "b"]},
            "null": {"sources": [{"name": "probe", "scheme": None}], "feedCacheDir": None},
        }
        dynamic = {"http": {"routers": {}, "middlewares": {}, "services": {"unused": {"loadBalancer": {"servers": [{"url": "http://127.0.0.1:1"}]}}}}}
        for name, config in cases.items():
            dynamic["http"]["middlewares"][name] = {"plugin": {"probe": config}}
            dynamic["http"]["routers"][name] = {"rule": 'Path(`/' + name + '`)', "middlewares": [name], "service": "unused"}
        (root / "dynamic.yml").write_text(json.dumps(dynamic))
        static = {"entryPoints": {"web": {"address": f"127.0.0.1:{port}"}}, "providers": {"file": {"filename": str(root / "dynamic.yml")}}, "experimental": {"localPlugins": {"probe": {"moduleName": "example.com/realclientv0"}}}, "log": {"level": "DEBUG"}, "global": {"checkNewVersion": False, "sendAnonymousUsage": False}}
        (root / "static.yml").write_text(json.dumps(static))
        with (output / "traefik.log").open("w") as log:
            process = subprocess.Popen([binary, "--configFile=" + str(root / "static.yml")], cwd=root, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 20
                while True:
                    try:
                        urllib.request.urlopen(f"http://127.0.0.1:{port}/nested", timeout=1).close()
                        break
                    except (OSError, urllib.error.URLError):
                        if process.poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError("Traefik did not become ready; inspect traefik.log")
                        time.sleep(0.1)
                results = []
                for name, expected in cases.items():
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/{name}", timeout=3) as response:
                        actual = json.load(response)
                    passed = actual == expected
                    results.append({"case": name, "passed": passed, "expected": expected, "actual": actual})
                    (output / "boundary.json").write_text(json.dumps(results, indent=2) + "\n")
                    print(("PASS " if passed else "CONTRADICTION ") + name, flush=True)
                    if not passed:
                        return 1
                return 0
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--traefik", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run(str(pathlib.Path(args.traefik).resolve()), args.output.resolve()))
