#!/usr/bin/env python3
"""Validate selected decoded config contracts with a synthetic preset; no V1 implementation."""
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
        shutil.copytree(pathlib.Path(__file__).parent / "config-plugin", plugin)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        # JSON is valid YAML; this keeps scalar types and expected data explicit.
        def source(**fields):
            return {"sources": [{"name": "probe", "preset": "v0", **fields}]}
        def feed(value, duration="1s"):
            return source(trust={"feeds": [{"url": "https://example.invalid/feed", "format": "lines", "minEntries": value, "refreshInterval": duration}]})
        cases = {
            "baseline": source(),
            "replacement": source(trust={"static": ["198.51.100.0/24"], "headerIn": {"name": "X-Zone", "values": ["yes"]}}, scheme={"header": "X-Scheme", "mode": "single"}),
            "null-inherits": source(scheme=None),
            "empty-feeds": source(trust={"feeds": []}),
            "unknown-extract-mode": source(extract={"header": "X-Real-Ip", "mode": "invalid"}),
            "unknown-scheme-mode": source(scheme={"header": "X-Forwarded-Proto", "mode": "invalid"}),
            "empty-static": source(trust={"static": []}),
            "empty-string-static": source(trust={"static": ""}),
            "empty-predicate-values": source(trust={"headerIn": {"name": "X-Zone", "values": []}}),
            "empty-sources": {"sources": []},
            "unknown-top": {**source(), "allowPrivateClient": True},
            "unknown-nested": source(trust={"headerEquals": {"value": "wrong"}}),
            "unknown-preset": {"sources": [{"name": "probe", "preset": "not-v0"}]},
            "decimal": feed("1"),
            "numeric": feed(1),
            "fraction": feed(1.5),
            "signed": feed("+1"),
            "spaces": feed(" 1"),
            "exponent": feed("1e2"),
            "overflow": feed("18446744073709551616"),
            "range": feed("100001"),
            "zero": feed("0"),
            "invalid-duration": feed("1", "fast"),
            "numeric-duration": feed("1", 2),
            "short-duration": feed("1", "500ms"),
        }
        valid = {"baseline", "replacement", "null-inherits", "decimal", "numeric"}
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
                    passed = (status == 200) == (name in valid)
                    if status == 200:
                        effective = actual["effective"]["sources"][0]
                        passed = passed and actual["inputUnchanged"] and effective["trust"]["static"] == (["198.51.100.0/24"] if name == "replacement" else ["192.0.2.0/24"])
                        passed = passed and effective["scheme"]["header"] == ("X-Scheme" if name == "replacement" else "X-Forwarded-Proto")
                    results[-1]["passed"] = passed
                    (output / "boundary.json").write_text(json.dumps(results, indent=2) + "\n")
                    print(("PASS " if passed else "CONTRADICTION ") + name, flush=True)
                    if not passed:
                        raise AssertionError(name)
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
