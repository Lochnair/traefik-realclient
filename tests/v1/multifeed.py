#!/usr/bin/env python3
"""Regression for the pangolin-sg production feed-matching failure (§6).

A source with two feeds -- the exact shape of the `bunny` preset (IPv4 `lines` +
IPv6 `json-array`). The trusted peer's IP lives ONLY in the first feed, mirroring
Bunny POPs, which are in the IPv4 edge list.

Under Yaegi 0.16.1 the plugin's `source.feeds []addressSource` slice made every
element alias the last worker, so `s.feeds` was `[ipv6Worker, ipv6Worker]`: the
IPv4 worker fetched and cached correctly but no request ever consulted it, and
every Bunny request fell back to the POP IP. `feeds.py` missed this because it
configures a single feed. This exercises the multi-feed path end to end through
real Traefik / Yaegi, across a 304 refresh and a restart (cache reload).

Run: python3 tests/v1/multifeed.py --traefik "$(command -v traefik)" --output /tmp/mf
"""
import argparse
import http.server
import json
import pathlib
import ssl
import threading
import time
import urllib.request

import harness

# The trusted peer a local test can produce is 127.0.0.1; place it only in the
# first (lines) feed. FILLER makes the feed non-trivial, like the real ~586.
FILLER4 = [f"84.17.{a}.{b}" for a in range(40, 50) for b in range(1, 51)]  # 500
V4_BODY = "\n".join(["127.0.0.1"] + FILLER4) + "\n"
V6_BODY = json.dumps(["2a02:6ea0:c700::1"] + [f"2a02:6ea0:c700:{i:x}::1" for i in range(1, 300)])
CLIENT = "203.0.113.77"


class Feed(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        six = self.path.endswith("ipv6")
        body = (V6_BODY if six else V4_BODY).encode()
        etag = '"v6"' if six else '"v4"'
        if self.headers.get("If-None-Match") == etag:
            self.send_response(304)
            self.send_header("ETag", etag)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("ETag", etag)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def run(binary, output):
    output.mkdir(parents=True, exist_ok=True)
    results = harness.Results(output / "results.json")
    backend = harness.start_backend()
    root = output / "root"
    root.mkdir(exist_ok=True)
    harness.stage_plugin(root)
    cert, key = harness.self_signed(root, cn="feed.test")

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Feed)
    fctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    fctx.load_cert_chain(cert, key)
    srv.socket = fctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    fp = srv.server_address[1]

    cache_dir = root / "cache"
    port = harness.freeport()
    src = {"name": "bunny", "trust": {"feeds": [
        {"url": f"https://127.0.0.1:{fp}/plain", "format": "lines",
         "refreshInterval": "2s", "minEntries": "1"},
        {"url": f"https://127.0.0.1:{fp}/ipv6", "format": "json-array",
         "refreshInterval": "2s", "minEntries": "1"}]},
        "extract": {"header": "X-Real-Ip", "mode": "single"}}
    dynamic = {"http": {
        "routers": {"main": {"rule": "PathPrefix(`/`)", "entryPoints": ["edge"], "service": "echo"}},
        "middlewares": {"realclient": {"plugin": {"realclient": {
            "feedCacheDir": str(cache_dir), "sources": [src]}}}},
        "services": {"echo": {"loadBalancer": {"servers": [
            {"url": f"http://127.0.0.1:{backend.server_port}"}]}}},
    }}
    (root / "dynamic.yml").write_text(json.dumps(dynamic))
    static = {
        "entryPoints": {"edge": {"address": f"127.0.0.1:{port}",
                                 "forwardedHeaders": {"insecure": True},
                                 "http": {"aliasHeadersStrategy": "delete",
                                          "middlewares": ["realclient@file"]}}},
        "providers": {"file": {"filename": str(root / "dynamic.yml")}},
        "experimental": {"localPlugins": {"realclient": {"moduleName": harness.MODULE}}},
        "log": {"level": "INFO"},
        "global": {"checkNewVersion": False, "sendAnonymousUsage": False},
    }
    tenv = {"SSL_CERT_FILE": cert, "GODEBUG": "x509sslcertoverrideplatform=1"}

    def resolved():
        req = urllib.request.Request(f"http://127.0.0.1:{port}/",
                                     headers={"X-Real-Ip": CLIENT})
        r = urllib.request.urlopen(req, timeout=5)
        return json.loads(r.read())["headers"].get("X-Real-Ip", [None])[0]

    def eventually(want, tries=40):
        for _ in range(tries):
            try:
                if resolved() == want:
                    return want
            except Exception:  # noqa: BLE001
                pass
            time.sleep(0.5)
        try:
            return resolved()
        except Exception as e:  # noqa: BLE001
            return repr(e)

    try:
        ready = lambda: _safe(resolved) in (CLIENT, "127.0.0.1")
        with harness.traefik(binary, root, static, output / "phase1", ready, env=tenv):
            # peer 127.0.0.1 is in feed[0]; the source must match and extraction wins.
            results.record("multi-feed: peer in first feed is trusted",
                           eventually(CLIENT) == CLIENT, resolved=_safe(resolved))
            time.sleep(4)  # force a 2s refresh -> conditional 304 -> snapshot re-store
            results.record("multi-feed: still trusted after a 304 refresh",
                           eventually(CLIENT) == CLIENT, resolved=_safe(resolved))
            files = sorted(cache_dir.glob("*.json")) if cache_dir.exists() else []
            results.record("multi-feed: both workers persisted a cache", len(files) == 2,
                           files=[f.name for f in files])
        with harness.traefik(binary, root, static, output / "phase2", ready, env=tenv):
            results.record("multi-feed: still trusted after restart (cache reload)",
                           eventually(CLIENT) == CLIENT, resolved=_safe(resolved))
        return results.finish()
    finally:
        srv.shutdown()
        backend.shutdown()
        backend.server_close()


def _safe(fn):
    try:
        return fn()
    except Exception as e:  # noqa: BLE001
        return repr(e)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--traefik", required=True)
    ap.add_argument("--output", type=pathlib.Path, required=True)
    a = ap.parse_args()
    raise SystemExit(run(str(pathlib.Path(a.traefik).resolve()), a.output.resolve()))
