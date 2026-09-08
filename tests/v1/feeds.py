#!/usr/bin/env python3
"""V1 dynamic-feed subsystem through the Yaegi-interpreted plugin (§6): a real
HTTPS feed server, the interpreted worker loop fetching / revalidating / caching
it, LKG retention on failure, and disk-cache persistence across a restart.

The plugin fetches feeds with normal certificate validation, so Traefik is run
with SSL_CERT_FILE pointing at the feed server's CA -- no plugin code changes.
"""
import argparse
import http.server
import json
import pathlib
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

import harness


class Feed(http.server.BaseHTTPRequestHandler):
    lock = threading.Lock()
    body = "127.0.0.1\n203.0.113.0/24\n"
    etag = '"v1"'
    status = 200
    hits = 0

    def do_GET(self):
        with Feed.lock:
            Feed.hits += 1
            status, body, etag = Feed.status, Feed.body, Feed.etag
        if status == 304 and self.headers.get("If-None-Match") == etag:
            self.send_response(304)
            self.send_header("ETag", etag)
            self.end_headers()
            return
        if status not in (200, 304):
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        payload = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        if etag:
            self.send_header("ETag", etag)
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):
        pass


def run(binary, output):
    output.mkdir(parents=True, exist_ok=True)
    results = harness.Results(output / "results.json")
    backend = harness.start_backend()

    with tempfile.TemporaryDirectory(prefix="realclient-v1-feeds-") as tmp:
        root = pathlib.Path(tmp)
        harness.stage_plugin(root)
        cert, key = harness.self_signed(root, cn="feed.test")
        feed_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Feed)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        feed_srv.socket = ctx.wrap_socket(feed_srv.socket, server_side=True)
        threading.Thread(target=feed_srv.serve_forever, daemon=True).start()
        feed_port = feed_srv.server_address[1]
        feed_url = f"https://127.0.0.1:{feed_port}/feed"

        vctx = ssl.create_default_context(cafile=cert)
        probe = urllib.request.urlopen(feed_url, timeout=5, context=vctx).read().decode()
        results.record("feed-server-serves-verified-tls", "127.0.0.1" in probe, body=probe[:40])

        cache_dir = root / "cache"
        port = harness.freeport()
        rc = {"name": "feeded", "trust": {"feeds": [
            {"url": feed_url, "format": "lines", "refreshInterval": "1s", "minEntries": "1"}]},
            "extract": {"header": "X-Real-Ip", "mode": "single"}}
        dynamic = {"http": {
            "routers": {"r": {"rule": "PathPrefix(`/`)", "entryPoints": ["edge"], "service": "echo",
                              "middlewares": ["realclient"]}},
            "middlewares": {"realclient": {"plugin": {"realclient": {
                "feedCacheDir": str(cache_dir), "sources": [rc]}}}},
            "services": {"echo": {"loadBalancer": {"servers": [{"url": f"http://127.0.0.1:{backend.server_port}"}]}}},
        }}
        (root / "dynamic.yml").write_text(json.dumps(dynamic))
        static = {
            "entryPoints": {"edge": {"address": f"127.0.0.1:{port}",
                                     "forwardedHeaders": {"insecure": True},
                                     "http": {"aliasHeadersStrategy": "delete"}}},
            "providers": {"file": {"filename": str(root / "dynamic.yml")}},
            "experimental": {"localPlugins": {"realclient": {"moduleName": harness.MODULE}}},
            "log": {"level": "INFO"},
            "global": {"checkNewVersion": False, "sendAnonymousUsage": False},
        }
        # Traefik's release build ships DefaultGODEBUG=x509sslcertoverrideplatform=0,
        # which makes macOS ignore SSL_CERT_FILE. Re-enable it so the plugin's feed
        # client (normal cert validation, by design) trusts the local feed CA.
        tenv = {"SSL_CERT_FILE": cert, "GODEBUG": "x509sslcertoverrideplatform=1"}

        def get(real_ip):
            req = urllib.request.Request(f"http://127.0.0.1:{port}/x", headers={"X-Real-Ip": real_ip})
            try:
                r = urllib.request.urlopen(req, timeout=5)
                return r.status, json.loads(r.read())["headers"]
            except urllib.error.HTTPError as e:
                return e.code, {}

        def resolved(real_ip):
            # source matches (peer 127.0.0.1 in the feed) -> extraction wins;
            # otherwise peer fallback leaves X-Real-Ip == 127.0.0.1.
            return get(real_ip)[1].get("X-Real-Ip", [None])[0]

        def eventually(fn, want, tries=25):
            for _ in range(tries):
                if fn() == want:
                    return want
                time.sleep(0.5)
            return fn()

        try:
            with harness.traefik(binary, root, static, output / "phase1",
                                 lambda: get("203.0.113.9")[0] == 200, env=tenv):
                # 1. the interpreted worker fetches the feed; the peer becomes trusted.
                got = eventually(lambda: resolved("203.0.113.9"), "203.0.113.9")
                results.record("feed-worker-fetches-and-trusts-peer", got == "203.0.113.9", resolved=got)

                # 2. disk cache written by the interpreted worker.
                files = list(cache_dir.glob("*.json")) if cache_dir.exists() else []
                cached = files[0].read_text() if files else ""
                results.record("feed-disk-cache-written",
                               bool(files) and "127.0.0.1" in cached and '"Validated"' in cached,
                               files=[f.name for f in files])

                # 3. a conditional 304 keeps the current representation.
                with Feed.lock:
                    Feed.status = 304
                time.sleep(3)
                results.record("conditional-304-keeps-set", resolved("203.0.113.9") == "203.0.113.9")

                # 4. a valid updated 200 that drops the peer is adopted -> fallback.
                with Feed.lock:
                    Feed.body, Feed.etag, Feed.status = "198.51.100.0/24\n", '"v2"', 200
                results.record("valid-update-adopted",
                               eventually(lambda: resolved("203.0.113.9"), "127.0.0.1") == "127.0.0.1")

                # 5. restore the peer, then an invalid 200 never replaces that LKG.
                with Feed.lock:
                    Feed.body, Feed.etag, Feed.status = "127.0.0.1\n203.0.113.0/24\n", '"v3"', 200
                eventually(lambda: resolved("203.0.113.9"), "203.0.113.9")
                with Feed.lock:
                    Feed.body, Feed.status = "not-an-ip\n", 200
                time.sleep(4)
                results.record("invalid-200-retains-lkg", resolved("203.0.113.9") == "203.0.113.9")

                # 6. a hard error also retains LKG.
                with Feed.lock:
                    Feed.status = 503
                time.sleep(4)
                results.record("http-error-retains-lkg", resolved("203.0.113.9") == "203.0.113.9")

            # 7. restart with the feed server down: the worker loads the persisted
            #    cache (the v3 set, which trusts the peer) before any fetch.
            feed_srv.shutdown()
            with harness.traefik(binary, root, static, output / "phase2",
                                 lambda: get("203.0.113.9")[0] == 200, env=tenv):
                r0 = eventually(lambda: resolved("203.0.113.9"), "203.0.113.9", tries=10)
                results.record("restart-loads-persisted-cache", r0 == "203.0.113.9", resolved=r0)
            return results.finish()
        finally:
            try:
                feed_srv.shutdown()
            except Exception:  # noqa: BLE001
                pass
            backend.shutdown()
            backend.server_close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--traefik", required=True)
    ap.add_argument("--output", type=pathlib.Path, required=True)
    a = ap.parse_args()
    raise SystemExit(run(str(pathlib.Path(a.traefik).resolve()), a.output.resolve()))
