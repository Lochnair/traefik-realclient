#!/usr/bin/env python3
"""Observe isolated package-global primitives through actual Yaegi. No feed implementation."""
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
        shutil.copytree(pathlib.Path(__file__).parent / "primitives-plugin", plugin)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        # JSON is valid YAML; this keeps scalar types and expected data explicit.
        cases = {"baseline": {"values": ["original"], "nested": {"inner": {"value": "original"}}}}
        dynamic = {"http": {"routers": {}, "middlewares": {}, "services": {"unused": {"loadBalancer": {"servers": [{"url": "http://127.0.0.1:1"}]}}}}}
        for name, config in cases.items():
            dynamic["http"]["middlewares"][name] = {"plugin": {"probe": config}}
            dynamic["http"]["routers"][name] = {"rule": 'Path(`/' + name + '`)', "middlewares": [name], "service": "unused"}
        dynamic["http"]["routers"]["second"] = {"rule": "Path(`/second`)", "middlewares": ["baseline"], "service": "unused"}
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
                for name in ["baseline", "second"]:
                    supplied = cases["baseline"]
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
                    if status != 200:
                        raise AssertionError("primitive construction failed")
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
