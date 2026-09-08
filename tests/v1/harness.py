#!/usr/bin/env python3
"""Shared helpers for the V1 Traefik-runtime integration suite.

Every harness loads the *real* plugin package (github.com/Lochnair/traefik-realclient)
as a Traefik local plugin, so it is exercised through Traefik 3.7.12 / Yaegi 0.16.1.
"""
import base64
import contextlib
import hashlib
import http.server
import json
import pathlib
import shutil
import socket
import subprocess
import threading
import time

REPO = pathlib.Path(__file__).resolve().parents[2]
MODULE = "github.com/Lochnair/traefik-realclient"
PLUGIN_SOURCES = ["address.go", "config.go", "feeds.go", "presets.go", "realclient.go", "resolver.go"]


def freeport():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def stage_plugin(root: pathlib.Path):
    """Copy the committed plugin package into a Traefik local-plugin tree."""
    dest = root / "plugins-local" / "src" / MODULE
    dest.mkdir(parents=True, exist_ok=True)
    for name in PLUGIN_SOURCES:
        shutil.copy(REPO / name, dest / name)
    shutil.copy(REPO / "go.mod", dest / "go.mod")
    shutil.copy(REPO / ".traefik.yml", dest / ".traefik.yml")
    return dest


def stage_local_plugin(root: pathlib.Path, module: str, repo: str, ref: str):
    """Download a third-party Traefik plugin as a local plugin (source tarball)."""
    import io
    import tarfile
    import urllib.request
    dest = root / "plugins-local" / "src" / module
    dest.mkdir(parents=True, exist_ok=True)
    url = f"https://codeload.github.com/{repo}/tar.gz/refs/tags/{ref}"
    data = urllib.request.urlopen(url, timeout=30).read()
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        members = [m for m in tar.getmembers() if m.isfile()]
        prefix = members[0].name.split("/")[0] + "/"
        for m in members:
            rel = m.name[len(prefix):]
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(tar.extractfile(m).read())
    return dest


def self_signed(root: pathlib.Path, cn="origin.test"):
    key, cert = root / "key.pem", root / "cert.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
         "-out", str(cert), "-days", "1", "-subj", "/CN=" + cn,
         "-addext", "subjectAltName=DNS:" + cn + ",DNS:localhost,IP:127.0.0.1"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return str(cert), str(key)


class EchoBackend(http.server.BaseHTTPRequestHandler):
    """Reports exactly what the backend observes after Traefik + the plugin."""
    protocol_version = "HTTP/1.1"
    release = threading.Event()

    def _emit(self):
        observed = {
            "method": self.command,
            "path": self.path,
            "remote_addr": self.client_address[0],
            "headers": {k: self.headers.get_all(k) for k in {h.lower(): h for h in self.headers.keys()}.values()},
            "raw_headers": [[k, v] for k, v in self.headers.items()],
        }
        body = json.dumps(observed).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        if self.path == "/__release":
            self.release.set()
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.headers.get("Upgrade", "").lower() == "websocket":
            key = self.headers["Sec-WebSocket-Key"]
            accept = base64.b64encode(hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.send_header("X-Effective", self.headers.get("X-Real-Ip", ""))
            self.send_header("X-Proto", self.headers.get("X-Forwarded-Proto", ""))
            self.end_headers()
            self.wfile.flush()
            frame = self.rfile.read(2)
            length = frame[1] & 127
            mask = self.rfile.read(4)
            data = self.rfile.read(length)
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            self.wfile.write(bytes([0x81, len(payload)]) + payload)
            self.wfile.flush()
            self.close_connection = True
            return
        if self.path.startswith("/stream"):
            self.release.clear()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "13")
            self.send_header("X-Effective", self.headers.get("X-Real-Ip", ""))
            self.send_header("X-Fwd-For", self.headers.get("X-Forwarded-For", ""))
            self.end_headers()
            self.wfile.write(b"first\n")
            self.wfile.flush()
            self.release.wait(5)
            self.wfile.write(b"second\n")
            self.wfile.flush()
            return
        self._emit()

    do_POST = do_GET
    do_PUT = do_GET
    do_HEAD = do_GET

    def log_message(self, *a):
        pass


def start_backend():
    backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), EchoBackend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    return backend


def _url_ready(ready_url):
    import urllib.request
    import urllib.error
    try:
        return urllib.request.urlopen(ready_url, timeout=1).status == 200
    except (OSError, urllib.error.HTTPError):
        return False


@contextlib.contextmanager
def traefik(binary, root: pathlib.Path, static: dict, logdir: pathlib.Path, ready, env=None):
    """`ready` is a URL string (polled for HTTP 200) or a zero-arg callable -> bool."""
    import os
    check = ready if callable(ready) else (lambda: _url_ready(ready))
    (root / "static.yml").write_text(json.dumps(static))
    logdir.mkdir(parents=True, exist_ok=True)
    with (logdir / "traefik.log").open("w") as log:
        proc = subprocess.Popen([binary, "--configFile=" + str(root / "static.yml")],
                                cwd=root, stdout=log, stderr=subprocess.STDOUT,
                                env={**os.environ, **(env or {})})
        try:
            deadline = time.monotonic() + 30
            while True:
                try:
                    if check():
                        break
                except OSError:
                    pass
                if proc.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("Traefik did not become ready; inspect " + str(logdir / "traefik.log"))
                time.sleep(0.15)
            yield proc
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


class Results:
    def __init__(self, path: pathlib.Path):
        self.path = path
        self.items = []
        self.failed = []

    def record(self, name, passed, **detail):
        self.items.append({"case": name, "passed": bool(passed), **detail})
        self.path.write_text(json.dumps(self.items, indent=2) + "\n")
        print(("PASS " if passed else "FAIL ") + name, flush=True)
        if not passed:
            self.failed.append(name)

    def finish(self):
        print("\n%d passed, %d failed" % (len(self.items) - len(self.failed), len(self.failed)), flush=True)
        return 1 if self.failed else 0
