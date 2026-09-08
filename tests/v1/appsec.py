#!/usr/bin/env python3
"""V1 CrowdSec AppSec integration (§7.2 / §9): a real CrowdSec AppSec component
in a disposable container, reached through the real bouncer plugin chained after
Realclient. Confirm that AppSec blocks an attack, allows a clean request, and
attributes the event to the Realclient-resolved identity.
"""
import argparse
import json
import pathlib
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

import harness

CS_IMAGE = "crowdsecurity/crowdsec:v1.6.4"
BOUNCER_MODULE = "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin"
BOUNCER_REPO = "maxlerebourg/crowdsec-bouncer-traefik-plugin"
BOUNCER_REF = "v1.7.1"

ACQUIS = """\
appsec_config: crowdsecurity/appsec-default
name: realclient-appsec
source: appsec
listen_addr: 0.0.0.0:7422
labels:
  type: appsec
"""


def dexec(name, *args, check=True):
    return subprocess.run(["docker", "exec", name, *args], check=check,
                          capture_output=True, text=True)


def appsec_probe(port, key, uri="/", verb="GET"):
    """Speak the bouncer<->AppSec protocol directly; returns the JSON verdict."""
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/", data=b"", method="POST",
        headers={"X-Crowdsec-Appsec-Api-Key": key, "X-Crowdsec-Appsec-Ip": "203.0.113.250",
                 "X-Crowdsec-Appsec-Uri": uri, "X-Crowdsec-Appsec-Host": "probe.test",
                 "X-Crowdsec-Appsec-Verb": verb})
    try:
        r = urllib.request.urlopen(req, timeout=5)
        return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {}


def wait_appsec(port, key, deadline):
    while time.monotonic() < deadline:
        try:
            st, _ = appsec_probe(port, key)
            if st in (200, 401, 403):
                return st == 200
        except OSError:
            pass
        time.sleep(1)
    return False


def run(binary, output):
    output.mkdir(parents=True, exist_ok=True)
    results = harness.Results(output / "results.json")
    backend = harness.start_backend()
    name = "rc-appsec-" + secrets.token_hex(4)
    key = secrets.token_hex(16)
    lapi_port, appsec_port = harness.freeport(), harness.freeport()
    container = None
    try:
        with tempfile.TemporaryDirectory(prefix="realclient-v1-appsec-") as tmp:
            root = pathlib.Path(tmp)
            (root / "appsec.yaml").write_text(ACQUIS)
            subprocess.run([
                "docker", "run", "-d", "--name", name,
                "-p", f"127.0.0.1:{lapi_port}:8080",
                "-p", f"127.0.0.1:{appsec_port}:7422",
                "-e", "DISABLE_ONLINE_API=true",
                "-e", f"BOUNCER_KEY_traefik={key}",
                "-e", "COLLECTIONS=crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules",
                "-v", f"{root / 'appsec.yaml'}:/etc/crowdsec/acquis.d/appsec.yaml:ro",
                CS_IMAGE], check=True, capture_output=True, text=True)
            container = name

            # appsec-default config is not a collection; install it then reload.
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                if dexec(name, "cscli", "lapi", "status", check=False).returncode == 0:
                    break
                time.sleep(1)
            dexec(name, "cscli", "appsec-configs", "install", "crowdsecurity/appsec-default", check=False)
            dexec(name, "cscli", "collections", "install",
                  "crowdsecurity/appsec-virtual-patching", "crowdsecurity/appsec-generic-rules", check=False)
            subprocess.run(["docker", "restart", name], check=True, capture_output=True)
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                if dexec(name, "cscli", "lapi", "status", check=False).returncode == 0:
                    break
                time.sleep(1)
            clean_ok = wait_appsec(appsec_port, key, time.monotonic() + 60)
            # confirm the rules are live: the .env probe rule must ban.
            atk_status, atk_verdict = appsec_probe(appsec_port, key, uri="/.env")
            results.record("appsec-component-up",
                           clean_ok and (atk_status == 403 or atk_verdict.get("action") == "ban"),
                           clean=clean_ok, attack_status=atk_status, attack_verdict=atk_verdict)

            harness.stage_plugin(root)
            harness.stage_local_plugin(root, BOUNCER_MODULE, BOUNCER_REPO, BOUNCER_REF)
            port = harness.freeport()
            rc = {"name": "edge", "trust": {"static": ["127.0.0.1/32"]},
                  "extract": {"header": "X-Real-Ip", "mode": "single"}}
            bouncer = {
                "enabled": True, "logLevel": "DEBUG", "crowdsecMode": "live",
                "crowdsecLapiScheme": "http", "crowdsecLapiHost": f"127.0.0.1:{lapi_port}",
                "crowdsecLapiKey": key, "defaultDecisionSeconds": 1,
                "metricsUpdateIntervalSeconds": 0,
                "crowdsecAppsecEnabled": True,
                "crowdsecAppsecScheme": "http",
                "crowdsecAppsecHost": f"127.0.0.1:{appsec_port}",
                "crowdsecAppsecKey": key,
                "forwardedHeadersCustomName": "X-Forwarded-For",
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

            def get(path, ip):
                req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers={"X-Real-Ip": ip})
                try:
                    return urllib.request.urlopen(req, timeout=8).status
                except urllib.error.HTTPError as e:
                    return e.code

            with harness.traefik(binary, root, static, output,
                                 lambda: get("/", "203.0.113.1") in (200, 403)):
                # 1. clean request passes AppSec.
                results.record("appsec-clean-request-allowed", get("/hello", "198.51.100.20") == 200)

                # 2. an obvious attack (.env exfiltration probe) is blocked by AppSec.
                st = 0
                for _ in range(6):
                    st = get("/.env", "198.51.100.30")
                    if st == 403:
                        break
                    time.sleep(1)
                results.record("appsec-attack-blocked", st == 403, status=st)

                # 3. AppSec attributes the event to the Realclient-resolved IP.
                time.sleep(3)
                alerts = dexec(name, "cscli", "alerts", "list", "-o", "json", check=False).stdout
                try:
                    parsed = json.loads(alerts) if alerts.strip() else []
                except json.JSONDecodeError:
                    parsed = []
                sources = {s for a in parsed for s in [a.get("source", {}).get("value")]}
                (output / "alerts.json").write_text(alerts or "[]")
                results.record("appsec-attributes-resolved-ip",
                               "198.51.100.30" in sources, sources=sorted(x for x in sources if x))
        return results.finish()
    finally:
        if container:
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
