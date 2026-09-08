#!/usr/bin/env python3
"""V1 CrowdSec bouncer integration (§7.2 / §9): a real CrowdSec LAPI in a
disposable container, the real bouncer plugin loaded through Yaegi, chained
after Realclient. Ban a resolved client, allow another, and confirm that a
fallback request is enforced on the peer.

AppSec is covered separately by appsec.py.
"""
import argparse
import json
import pathlib
import secrets
import subprocess
import tempfile
import time
import urllib.request

import harness

CS_IMAGE = "crowdsecurity/crowdsec:v1.6.4"
BOUNCER_MODULE = "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin"
BOUNCER_REPO = "maxlerebourg/crowdsec-bouncer-traefik-plugin"
BOUNCER_REF = "v1.7.1"


def dexec(name, *args, check=True):
    return subprocess.run(["docker", "exec", name, *args], check=check,
                          capture_output=True, text=True).stdout


def wait_lapi(port, deadline):
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2).close()
            return True
        except urllib.error.HTTPError:
            return True
        except OSError:
            time.sleep(0.5)
    return False


def run(binary, output):
    output.mkdir(parents=True, exist_ok=True)
    results = harness.Results(output / "results.json")
    backend = harness.start_backend()
    name = "rc-cs-" + secrets.token_hex(4)
    key = secrets.token_hex(16)
    lapi_port = harness.freeport()
    container = None
    try:
        subprocess.run([
            "docker", "run", "-d", "--name", name,
            "-p", f"127.0.0.1:{lapi_port}:8080",
            "-e", "DISABLE_ONLINE_API=true", "-e", "DISABLE_AGENT=true",
            "-e", f"BOUNCER_KEY_traefik={key}",
            CS_IMAGE], check=True, capture_output=True, text=True)
        container = name
        if not wait_lapi(lapi_port, time.monotonic() + 60):
            raise RuntimeError("CrowdSec LAPI did not come up")
        # let the entrypoint register the bouncer key
        for _ in range(30):
            if "traefik" in dexec(name, "cscli", "bouncers", "list", "-o", "raw"):
                break
            time.sleep(1)

        dexec(name, "cscli", "decisions", "add", "--ip", "198.51.100.66", "--duration", "2h", "--type", "ban")

        with tempfile.TemporaryDirectory(prefix="realclient-v1-cs-") as tmp:
            root = pathlib.Path(tmp)
            harness.stage_plugin(root)
            harness.stage_local_plugin(root, BOUNCER_MODULE, BOUNCER_REPO, BOUNCER_REF)
            port = harness.freeport()

            rc = {"name": "edge", "trust": {"static": ["127.0.0.1/32"]},
                  "extract": {"header": "X-Real-Ip", "mode": "single"}}
            bouncer = {
                "enabled": True,
                "logLevel": "INFO",
                "crowdsecMode": "live",
                "crowdsecLapiScheme": "http",
                "crowdsecLapiHost": f"127.0.0.1:{lapi_port}",
                "crowdsecLapiKey": key,
                "forwardedHeadersCustomName": "X-Forwarded-For",
                "defaultDecisionSeconds": 1,
                "metricsUpdateIntervalSeconds": 0,
            }
            dynamic = {"http": {
                "routers": {"r": {"rule": "PathPrefix(`/`)", "entryPoints": ["edge"], "service": "echo",
                                  "middlewares": ["realclient", "crowdsec"]}},
                "middlewares": {
                    "realclient": {"plugin": {"realclient": {"sources": [rc]}}},
                    "crowdsec": {"plugin": {"crowdsec": bouncer}},
                },
                "services": {"echo": {"loadBalancer": {"servers": [{"url": f"http://127.0.0.1:{backend.server_port}"}]}}},
            }}
            (root / "dynamic.yml").write_text(json.dumps(dynamic))
            static = {
                "entryPoints": {"edge": {"address": f"127.0.0.1:{port}",
                                         "forwardedHeaders": {"insecure": True},
                                         "http": {"aliasHeadersStrategy": "delete"}}},
                "providers": {"file": {"filename": str(root / "dynamic.yml")}},
                "experimental": {"localPlugins": {
                    "realclient": {"moduleName": harness.MODULE},
                    "crowdsec": {"moduleName": BOUNCER_MODULE}}},
                "log": {"level": "INFO"},
                "global": {"checkNewVersion": False, "sendAnonymousUsage": False},
            }

            def get(ip):
                req = urllib.request.Request(f"http://127.0.0.1:{port}/x", headers={"X-Real-Ip": ip})
                try:
                    r = urllib.request.urlopen(req, timeout=5)
                    return r.status, r.read().decode()
                except urllib.error.HTTPError as e:
                    return e.code, e.read().decode()

            def eventually(ip, want, tries=8):
                # live-mode clean/ban results are cached for defaultDecisionSeconds.
                for _ in range(tries):
                    st = get(ip)[0]
                    if st == want:
                        return st
                    time.sleep(1)
                return st

            with harness.traefik(binary, root, static, output,
                                 lambda: get("203.0.113.1")[0] in (200, 403)):
                # 1. a resolved client that is banned in LAPI -> blocked.
                st, _ = get("198.51.100.66")
                results.record("banned-resolved-client-blocked", st == 403, status=st)

                # 2. a different resolved client -> allowed.
                st, body = get("198.51.100.77")
                ok = st == 200 and json.loads(body)["headers"].get("X-Real-Ip") == ["198.51.100.77"]
                results.record("unbanned-resolved-client-allowed", ok, status=st)

                # 3. malformed identity -> peer fallback; the bouncer enforces on the
                #    peer (127.0.0.1), which is not banned -> allowed.
                st, body = get("not-an-ip")
                ok = st == 200 and json.loads(body)["headers"].get("X-Real-Ip") == ["127.0.0.1"]
                results.record("fallback-request-enforced-on-peer-allowed", ok, status=st)

                # 4. ban the peer -> the same fallback request is now blocked, proving
                #    the bouncer keys on the resolved/peer identity, not the forged header.
                dexec(name, "cscli", "decisions", "add", "--ip", "127.0.0.1", "--duration", "2h", "--type", "ban")
                st = eventually("not-an-ip", 403)
                results.record("fallback-request-enforced-on-peer-blocked", st == 403, status=st)
                dexec(name, "cscli", "decisions", "delete", "--ip", "127.0.0.1", check=False)
                eventually("not-an-ip", 200)

                # 5. forged XFF cannot smuggle a ban past the resolved identity: an
                #    allowed resolved client with a banned IP in a forged XFF still 200s.
                req = urllib.request.Request(f"http://127.0.0.1:{port}/x",
                                             headers={"X-Real-Ip": "198.51.100.77",
                                                      "X-Forwarded-For": "198.51.100.66"})
                try:
                    st = urllib.request.urlopen(req, timeout=5).status
                except urllib.error.HTTPError as e:
                    st = e.code
                results.record("forged-xff-does-not-change-verdict", st == 200, status=st)
        return results.finish()
    finally:
        if container:
            subprocess.run(["docker", "logs", container], capture_output=True, text=True,
                           check=False).stdout
            (output / "crowdsec.log").write_text(
                subprocess.run(["docker", "logs", container], capture_output=True, text=True, check=False).stdout
                + subprocess.run(["docker", "logs", container], capture_output=True, text=True, check=False).stderr)
            subprocess.run(["docker", "rm", "-f", container], capture_output=True, check=False)
        backend.shutdown()
        backend.server_close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--traefik", required=True)
    ap.add_argument("--output", type=pathlib.Path, required=True)
    a = ap.parse_args()
    raise SystemExit(run(str(pathlib.Path(a.traefik).resolve()), a.output.resolve()))
