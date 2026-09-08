#!/usr/bin/env python3
"""Observe typed config and remain maps through the actual adapter. No V1 behavior."""
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
        shutil.copytree(pathlib.Path(__file__).parent / "plugin", plugin)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        # JSON is valid YAML; this keeps scalar types and expected data explicit.
        def source(**fields):
            return {"sources": [{"name": "probe", **fields}]}

        cases = {
            "baseline": source(),
            "trust-empty": source(trust={}),
            "static-omitted": source(trust={"feeds": [{"url": "https://example.invalid/feed"}]}),
            "static-empty": source(trust={"static": []}),
            "static-string": source(trust={"static": ""}),
            "static-null": source(trust={"static": None}),
            "static-valid": source(trust={"static": ["192.0.2.0/24"]}),
            "feeds-empty": source(trust={"feeds": []}),
            "sources-empty": {"sources": []},
            "sources-omitted": {"feedCacheDir": "/unused"},
            "scheme-empty": source(scheme={}),
            "scheme-null": source(scheme=None),
            "scheme-string": source(scheme=""),
            "scheme-valid": source(scheme={"header": "X-Forwarded-Proto", "mode": "single"}),
            "unknown-top": {**source(), "unexpectedTop": {"value": "kept"}},
            "unknown-source": source(unexpectedSource="kept"),
            "unknown-trust": source(trust={"unexpectedTrust": "kept"}),
            "unknown-feed": source(trust={"feeds": [{"url": "https://example.invalid/feed", "unexpectedFeed": "kept"}]}),
            "unknown-extract": source(extract={"header": "X-Real-Ip", "mode": "single", "unexpectedExtract": "kept"}),
            "unknown-scheme": source(scheme={"header": "X-Forwarded-Proto", "mode": "single", "unexpectedScheme": "kept"}),
            "unknown-headerIn": source(trust={"headerIn": {"name": "X-Zone", "values": ["one"], "unexpectedHeaderIn": "kept"}}),
            "unknown-hostExact": source(trust={"hostExact": {"header": "X-Host", "values": ["example.com"], "unexpectedHostExact": "kept"}}),
            "unknown-hostSuffixes": source(trust={"hostSuffixes": {"header": "X-Host", "suffixes": ["example.com"], "unexpectedHostSuffixes": "kept"}}),
        }
        dynamic = {"http": {"routers": {}, "middlewares": {}, "services": {"unused": {"loadBalancer": {"servers": [{"url": "http://127.0.0.1:1"}]}}}}}
        for name, config in cases.items():
            dynamic["http"]["middlewares"][name] = {"plugin": {"probe": config}}
            dynamic["http"]["routers"][name] = {"rule": 'Path(`/' + name + '`)', "middlewares": [name], "service": "unused"}
        (root / "dynamic.yml").write_text(json.dumps(dynamic))
        (output / "supplied.json").write_text(json.dumps(cases, indent=2) + "\n")
        static = {"entryPoints": {"web": {"address": f"127.0.0.1:{port}"}}, "providers": {"file": {"filename": str(root / "dynamic.yml")}}, "experimental": {"localPlugins": {"probe": {"moduleName": "example.com/realclientv0"}}}, "log": {"level": "DEBUG"}, "global": {"checkNewVersion": False, "sendAnonymousUsage": False}}
        (root / "static.yml").write_text(json.dumps(static))
        with (output / "traefik.log").open("w") as log:
            process = subprocess.Popen([binary, "--configFile=" + str(root / "static.yml")], cwd=root, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 20
                while True:
                    try:
                        urllib.request.urlopen(f"http://127.0.0.1:{port}/baseline", timeout=1).close()
                        break
                    except (OSError, urllib.error.URLError):
                        if process.poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError("Traefik did not become ready; inspect traefik.log")
                        time.sleep(0.1)
                results = []
                for name, supplied in cases.items():
                    try:
                        response = urllib.request.urlopen(f"http://127.0.0.1:{port}/{name}", timeout=3)
                    except urllib.error.HTTPError as error:
                        response = error
                    with response:
                        body = response.read().decode()
                        status = response.status
                    actual = json.loads(body) if status == 200 else None
                    results.append({"case": name, "supplied": supplied, "http_status": status,
                                    "new_receives": actual, "response_body": body if status != 200 else None})
                    (output / "boundary.json").write_text(json.dumps(results, indent=2) + "\n")
                    print(f"OBSERVED {name}: HTTP {status}", flush=True)
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
