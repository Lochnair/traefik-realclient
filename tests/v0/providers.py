#!/usr/bin/env python3
"""Actual Docker-label and Redis-KV paths into the V0 typed config probe."""
import argparse
import http.client
import json
import pathlib
import shutil
import socket
import subprocess
import tempfile
import time
import uuid

IMAGE = "redis@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf"

def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()

def run(binary, output):
    output.mkdir(parents=True, exist_ok=True)
    identity = "realclient-v0-" + uuid.uuid4().hex
    cases = {
        "good": {"sources[0].name": "probe", "sources[0].preset": "v0", "sources[0].trust.feeds[0].url": "https://example.invalid/feed", "sources[0].trust.feeds[0].format": "lines", "sources[0].trust.feeds[0].refreshInterval": "1s", "sources[0].trust.feeds[0].minEntries": "1"},
        "unknown": {"sources[0].name": "probe", "sources[0].preset": "v0", "sources[0].trust.headerEquals.value": "wrong"},
        "fraction": {"sources[0].name": "probe", "sources[0].preset": "v0", "sources[0].trust.feeds[0].minEntries": "1.5"},
        "empty": {"sources[0].name": "probe", "sources[0].preset": "v0", "sources[0].trust.static": ""},
    }
    labels = {"realclient.v0": identity, "traefik.enable": "true", "traefik.http.services.fixture.loadbalancer.server.port": "6379"}
    for case, values in cases.items():
        name = "docker-" + case
        labels.update({f"traefik.http.routers.{name}.rule": f"Path(`/{name}`)", f"traefik.http.routers.{name}.service": "noop@internal", f"traefik.http.routers.{name}.middlewares": name})
        labels.update({f"traefik.http.middlewares.{name}.plugin.probe.{key}": value for key, value in values.items()})
    args = ["run", "--detach", "--rm", "--name", identity, "--publish", "127.0.0.1::6379"]
    for key, value in labels.items():
        args += ["--label", key + "=" + value]
    args += [IMAGE, "redis-server", "--save", "", "--appendonly", "no"]
    container = docker(*args)
    try:
        redis_port = int(docker("port", container, "6379/tcp").rsplit(":", 1)[1])
        endpoint = docker("context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
        pairs = {}
        for case, values in cases.items():
            name = "redis-" + case
            pairs.update({f"{identity}/http/routers/{name}/rule": f"Path(`/{name}`)", f"{identity}/http/routers/{name}/service": "noop@internal", f"{identity}/http/routers/{name}/middlewares/0": name})
            for key, value in values.items():
                key = key.replace("[0]", "/0").replace(".", "/")
                pairs[f"{identity}/http/middlewares/{name}/plugin/probe/{key}"] = value
        deadline = time.monotonic() + 10
        while True:
            try:
                redis = socket.create_connection(("127.0.0.1", redis_port), timeout=2)
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(.1)
        with redis, redis.makefile("rb") as reply:
            for key, value in pairs.items():
                fields = [b"SET", key.encode(), value.encode()]
                redis.sendall(b"*3\r\n" + b"".join(b"$" + str(len(field)).encode() + b"\r\n" + field + b"\r\n" for field in fields))
                assert reply.readline() == b"+OK\r\n"
        (output / "labels.json").write_text(json.dumps(labels, indent=2) + "\n")
        (output / "kv.json").write_text(json.dumps(pairs, indent=2) + "\n")
        (output / "image.txt").write_text(IMAGE + "\n")
        with tempfile.TemporaryDirectory(prefix="realclient-provider-") as tmp:
            root = pathlib.Path(tmp)
            shutil.copytree(pathlib.Path(__file__).parent / "config-plugin", root / "plugins-local/src/example.com/realclientv0")
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            static = {"entryPoints": {"web": {"address": f"127.0.0.1:{port}"}},
                      "providers": {"docker": {"endpoint": endpoint, "exposedByDefault": False, "constraints": f"Label(`realclient.v0`, `{identity}`)"}, "redis": {"endpoints": [f"127.0.0.1:{redis_port}"], "rootKey": identity}},
                      "experimental": {"localPlugins": {"probe": {"moduleName": "example.com/realclientv0"}}},
                      "log": {"level": "DEBUG"}, "global": {"checkNewVersion": False, "sendAnonymousUsage": False}}
            (root / "static.yml").write_text(json.dumps(static))
            with (output / "traefik.log").open("w") as log:
                process = subprocess.Popen([binary, "--configFile=" + str(root / "static.yml")], cwd=root, stdout=log, stderr=subprocess.STDOUT)
                try:
                    def request(name):
                        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                        connection.request("GET", "/" + name)
                        response = connection.getresponse()
                        body = response.read().decode()
                        status = response.status
                        connection.close()
                        return status, json.loads(body) if status == 200 else body
                    deadline = time.monotonic() + 25
                    while True:
                        try:
                            if all(request(provider + "-good")[0] == 200 for provider in ["docker", "redis"]):
                                break
                        except OSError:
                            pass
                        if process.poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError("provider startup/good-case failed; inspect traefik.log")
                        time.sleep(.1)
                    results = []
                    for provider in ["docker", "redis"]:
                        for case in cases:
                            status, actual = request(provider + "-" + case)
                            # Redis drops zero-length values before typed decoding. This is
                            # omission under the reviewed decoded-value contract.
                            redis_omission = provider == "redis" and case == "empty"
                            passed = status == (200 if case == "good" or redis_omission else 404)
                            if redis_omission and status == 200:
                                passed = passed and actual["decoded"]["sources"][0]["trust"] is None and actual["effective"]["sources"][0]["trust"]["static"] == ["192.0.2.0/24"]
                            if case == "good" and status == 200:
                                feed = actual["decoded"]["sources"][0]["trust"]["feeds"][0]
                                passed = passed and feed["minEntries"] == "1" and feed["refreshInterval"] == "1s" and actual["inputUnchanged"]
                            results.append({"case": provider + "-" + case, "passed": passed, "status": status, "actual": actual})
                            (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
                            print(("PASS " if passed else "CONTRADICTION ") + provider + "-" + case, flush=True)
                            if not passed:
                                raise AssertionError(provider + "-" + case)
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
    finally:
        docker("rm", "--force", container)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--traefik", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    run(str(pathlib.Path(args.traefik).resolve()), args.output.resolve())
