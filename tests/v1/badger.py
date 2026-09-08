#!/usr/bin/env python3
"""V1 Badger (Pangolin) integration (§7.2 / §9): the real fosrl/badger plugin
loaded through Yaegi, configured as documented (disableDefaultCFIPs: true,
trustip: [], customIPHeader: ""), chained after Realclient. A mock Pangolin
verify-session API captures exactly what Badger computed so we can confirm it
uses the Realclient-normalized address and does not rebuild XFF or reinterpret
CDN headers.
"""
import argparse
import http.server
import json
import pathlib
import tempfile
import threading
import urllib.error
import urllib.request

import harness

BADGER_MODULE = "github.com/fosrl/badger"
BADGER_REPO = "fosrl/badger"
BADGER_REF = "v1.7.0"


class PangolinMock(http.server.BaseHTTPRequestHandler):
    last = {}
    verdict = {"valid": True}

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        PangolinMock.last = payload
        body = json.dumps({"data": {**{"valid": False, "redirectUrl": None}, **PangolinMock.verdict}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def run(binary, output):
    output.mkdir(parents=True, exist_ok=True)
    results = harness.Results(output / "results.json")
    backend = harness.start_backend()
    pangolin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), PangolinMock)
    threading.Thread(target=pangolin.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix="realclient-v1-badger-") as tmp:
            root = pathlib.Path(tmp)
            harness.stage_plugin(root)
            try:
                harness.stage_local_plugin(root, BADGER_MODULE, BADGER_REPO, BADGER_REF)
            except Exception as e:  # noqa: BLE001
                results.record("badger-source-staged", False, error=str(e))
                return results.finish()
            port = harness.freeport()

            rc = {"name": "edge", "trust": {"static": ["127.0.0.1/32"]},
                  "extract": {"header": "X-Real-Ip", "mode": "single"},
                  "scheme": {"header": "X-Forwarded-Proto", "mode": "single"}}
            badger = {
                "apiBaseUrl": f"http://127.0.0.1:{pangolin.server_port}/api/v1",
                "userSessionCookieName": "p_session_token",
                "resourceSessionRequestParam": "p_session_request",
                "disableDefaultCFIPs": True,
                "trustip": [],
                "customIPHeader": "",
            }
            dynamic = {"http": {
                "routers": {"r": {"rule": "PathPrefix(`/`)", "entryPoints": ["edge"], "service": "echo",
                                  "middlewares": ["realclient", "badger"]}},
                "middlewares": {
                    "realclient": {"plugin": {"realclient": {"sources": [rc]}}},
                    "badger": {"plugin": {"badger": badger}},
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
                    "badger": {"moduleName": BADGER_MODULE}}},
                "log": {"level": "INFO"},
                "global": {"checkNewVersion": False, "sendAnonymousUsage": False},
            }

            def get(ip, extra=None):
                h = {"X-Real-Ip": ip, **(extra or {})}
                req = urllib.request.Request(f"http://127.0.0.1:{port}/app", headers=h)
                try:
                    r = urllib.request.urlopen(req, timeout=6)
                    return r.status, r.read().decode()
                except urllib.error.HTTPError as e:
                    return e.code, e.read().decode()

            PangolinMock.verdict = {"valid": True}
            with harness.traefik(binary, root, static, output, lambda: get("203.0.113.1")[0] in (200, 401)):
                results.record("badger-loads-in-yaegi", True)

                # 1. valid session: Badger allowed the request and told Pangolin the
                #    Realclient-resolved IP, not a forged CDN header.
                st, body = get("198.51.100.40", {"Cf-Connecting-Ip": "1.2.3.4", "X-Forwarded-For": "9.9.9.9"})
                sent = PangolinMock.last
                bh = {k.lower(): v for k, v in json.loads(body)["headers"].items()} if st == 200 else {}
                results.record("badger-uses-resolved-ip",
                               st == 200 and sent.get("requestIp") == "198.51.100.40",
                               status=st, requestIp=sent.get("requestIp"))

                # 2. Badger did not rebuild XFF: the backend sees one effective entry
                #    (Traefik's append), and Badger's X-Real-Ip matches the resolved IP.
                results.record("badger-does-not-rebuild-xff",
                               bh.get("x-forwarded-for") == ["198.51.100.40"]
                               and bh.get("x-real-ip") == ["198.51.100.40"],
                               xff=bh.get("x-forwarded-for"), xri=bh.get("x-real-ip"))

                # 3. Badger forwarded no resurrected CDN identity channel to Pangolin.
                fwd = {k.lower() for k in sent.get("headers", {})}
                results.record("badger-no-cdn-channel-forwarded",
                               "cf-connecting-ip" not in fwd and "forwarded" not in fwd,
                               forwarded_headers=sorted(fwd))

                # 4. invalid session -> enforcement (401) on the resolved identity.
                PangolinMock.verdict = {"valid": False}
                st, _ = get("198.51.100.41")
                results.record("badger-denies-on-resolved-identity",
                               st == 401 and PangolinMock.last.get("requestIp") == "198.51.100.41", status=st)

                # 5. peer fallback path: malformed identity -> Badger sees the peer.
                PangolinMock.verdict = {"valid": True}
                st, _ = get("not-an-ip")
                results.record("badger-peer-fallback",
                               st == 200 and PangolinMock.last.get("requestIp") == "127.0.0.1",
                               status=st, requestIp=PangolinMock.last.get("requestIp"))
        return results.finish()
    finally:
        pangolin.shutdown()
        backend.shutdown()
        backend.server_close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--traefik", required=True)
    ap.add_argument("--output", type=pathlib.Path, required=True)
    a = ap.parse_args()
    raise SystemExit(run(str(pathlib.Path(a.traefik).resolve()), a.output.resolve()))
