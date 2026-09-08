#!/usr/bin/env python3
"""Real Traefik core V0 boundary probes; stop on a contract contradiction."""
import argparse
import base64
import hashlib
import http.client
import http.server
import json
import pathlib
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time

class Backend(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    gate = threading.Event()
    def do_GET(self):
        if self.path == "/release":
            self.gate.set()
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.startswith("/covered/stream"):
            self.gate.clear()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("X-V0-Effective", self.headers.get("X-Real-Ip", ""))
            self.send_header("Content-Length", "13")
            self.end_headers()
            self.wfile.write(b"first\n")
            self.wfile.flush()
            if not self.gate.wait(5):
                return
            self.wfile.write(b"second\n")
            self.wfile.flush()
            return
        if self.headers.get("Upgrade", "").lower() == "websocket":
            key = self.headers["Sec-WebSocket-Key"]
            accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.send_header("X-V0-Effective", self.headers.get("X-Real-Ip", ""))
            self.end_headers()
            self.wfile.flush()
            frame = self.rfile.read(2)
            length = frame[1] & 127
            mask = self.rfile.read(4)
            data = self.rfile.read(length)
            payload = bytes(value ^ mask[i % 4] for i, value in enumerate(data))
            self.wfile.write(bytes([0x81, len(payload)]) + payload)
            self.wfile.flush()
            self.close_connection = True
            return
        body = json.dumps({"headers": dict(self.headers), "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

def freeport():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

def run(binary, output):
    output.mkdir(parents=True, exist_ok=True)
    (output / "access.jsonl").unlink(missing_ok=True)
    backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    results = []
    try:
        with tempfile.TemporaryDirectory(prefix="realclient-runtime-") as tmp:
            root = pathlib.Path(tmp)
            shutil.copytree(pathlib.Path(__file__).parent / "runtime-plugin", root / "plugins-local/src/example.com/realclientv0")
            ports = {name: freeport() for name in ["secure", "insecure", "allowed", "reverse", "selector", "selectorallowed", "proxy", "tls"]}
            entrypoints = {}
            for name, port in ports.items():
                forwarded = {"insecure": name != "secure"}
                if name in ["allowed", "selectorallowed"]:
                    forwarded["connection"] = ["X-Custom-Ip", "X-Zone"]
                entrypoints[name] = {"address": f"127.0.0.1:{port}", "forwardedHeaders": forwarded,
                                     "http": {"middlewares": [name + "@file"], "aliasHeadersStrategy": "delete"}}
            entrypoints["insecure"]["http"]["encodedCharacters"] = {"allowEncodedSlash": False}
            entrypoints["proxy"]["proxyProtocol"] = {"trustedIPs": ["127.0.0.1/32"]}
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(root / "key.pem"), "-out", str(root / "cert.pem"), "-days", "1", "-subj", "/CN=a.example"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            static = {"entryPoints": entrypoints, "providers": {"file": {"filename": str(root / "dynamic.yml")}},
                      "experimental": {"localPlugins": {"probe": {"moduleName": "example.com/realclientv0"}}},
                      "log": {"level": "DEBUG"}, "global": {"checkNewVersion": False, "sendAnonymousUsage": False},
                      "ping": {"entryPoint": "insecure"},
                      "accessLog": {"addInternals": True, "format": "json", "filePath": str(output / "access.jsonl"), "bufferingSize": 10,
                                    "fields": {"headers": {"defaultMode": "keep"}}}}
            dynamic = {"http": {"routers": {}, "middlewares": {}, "services": {"echo": {"loadBalancer": {"servers": [{"url": f"http://127.0.0.1:{backend.server_port}"}]}}}}}
            for name in ports:
                inputs = ["X-Real-Ip", "X-Custom-Ip"] if name == "reverse" else ["X-Custom-Ip", "X-Real-Ip"]
                config = {"inputs": inputs}
                if name.startswith("selector"):
                    config["selector"] = "X-Zone"
                dynamic["http"]["middlewares"][name] = {"plugin": {"probe": config}}
                dynamic["http"]["routers"][name] = {"rule": "PathPrefix(`/covered`)", "entryPoints": [name], "service": "echo"}
            dynamic["http"]["routers"].update({
                "root-peer": {"rule": "Path(`/root-peer`) && ClientIP(`127.0.0.1/32`)", "entryPoints": ["insecure"], "service": "echo"},
                "root-effective": {"rule": "Path(`/root-effective`) && ClientIP(`198.51.100.2/32`)", "entryPoints": ["insecure"], "service": "echo"},
                "parent": {"rule": "PathPrefix(`/parent`)", "entryPoints": ["insecure"]},
                "child": {"rule": "Path(`/parent/child`) && ClientIP(`198.51.100.2/32`)", "parentRefs": ["parent"], "service": "echo"},
                "tls-a": {"rule": "Host(`a.example`)", "entryPoints": ["tls"], "service": "echo", "tls": {"options": "a"}},
                "tls-b": {"rule": "Host(`b.example`)", "entryPoints": ["tls"], "service": "echo", "tls": {"options": "b"}},
            })
            del dynamic["http"]["routers"]["tls"]
            dynamic["tls"] = {"certificates": [{"certFile": str(root / "cert.pem"), "keyFile": str(root / "key.pem")}], "options": {"a": {"minVersion": "VersionTLS12"}, "b": {"minVersion": "VersionTLS13"}}}
            subprocess.run(["go", "build", "-o", str(root / "http2-client"), str(pathlib.Path(__file__).parent.resolve() / "http2-client/main.go")], check=True)
            (root / "static.yml").write_text(json.dumps(static))
            (root / "dynamic.yml").write_text(json.dumps(dynamic))
            (output / "static.json").write_text(json.dumps(static, indent=2))
            (output / "dynamic.json").write_text(json.dumps(dynamic, indent=2))
            with (output / "traefik.log").open("w") as log:
                proc = subprocess.Popen([binary, "--configFile=" + str(root / "static.yml")], cwd=root, stdout=log, stderr=subprocess.STDOUT)
                try:
                    def request(entry, path, headers):
                        conn = http.client.HTTPConnection("127.0.0.1", ports[entry], timeout=3)
                        conn.request("GET", path, headers=headers)
                        response = conn.getresponse()
                        body = response.read().decode()
                        status = response.status
                        conn.close()
                        return status, json.loads(body) if status == 200 and body.startswith("{") else body
                    deadline = time.monotonic() + 20
                    while True:
                        try:
                            if request("secure", "/covered/ready", {})[0] == 200:
                                break
                        except OSError:
                            pass
                        if proc.poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError("runtime startup failed; inspect traefik.log")
                        time.sleep(.1)
                    def check(name, entry, headers, predicate, path=None):
                        status, response = request(entry, path or "/covered/" + name, headers)
                        actual = {"status": status, "response": response}
                        passed = predicate(actual)
                        results.append({"case": name, "passed": passed, **actual})
                        (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
                        print(("PASS " if passed else "CONTRADICTION ") + name, flush=True)
                        if not passed:
                            raise AssertionError(name)
                    def head(a):
                        return {k.lower(): v for k, v in a["response"]["headers"].items()}
                    def before(a):
                        return json.loads(head(a)["x-v0-before"])
                    check("secure-strips", "secure", {"X-Real-Ip": "198.51.100.1", "X-Forwarded-Proto": "https"},
                          lambda a: before(a)["Headers"]["X-Real-Ip"] == ["127.0.0.1"] and before(a)["Headers"]["X-Forwarded-Proto"] == ["http"])
                    check("insecure-preserves", "insecure", {"X-Real-Ip": "198.51.100.1", "X-Forwarded-Proto": "https"},
                          lambda a: before(a)["Headers"]["X-Real-Ip"] == ["198.51.100.1"] and before(a)["Headers"]["X-Forwarded-Proto"] == ["https"])
                    check("synthesized-preempts", "reverse", {"X-Custom-Ip": "198.51.100.2"},
                          lambda a: head(a)["x-v0-selected"] == "X-Real-Ip" and head(a)["x-real-ip"] == "127.0.0.1" and before(a)["Headers"]["X-Forwarded-Proto"] == ["http"])
                    check("informative-first", "insecure", {"X-Custom-Ip": "198.51.100.2"},
                          lambda a: head(a)["x-v0-selected"] == "X-Custom-Ip" and head(a)["x-real-ip"] == "198.51.100.2")
                    check("invalid-continues", "reverse", {"X-Real-Ip": "invalid", "X-Custom-Ip": "198.51.100.2"},
                          lambda a: head(a)["x-v0-selected"] == "X-Custom-Ip")
                    check("connection-removes-identity", "insecure", {"Connection": "X-Custom-Ip", "X-Custom-Ip": "198.51.100.2"},
                          lambda a: "X-Custom-Ip" not in before(a)["Headers"] and head(a)["x-v0-selected"] == "X-Real-Ip")
                    check("connection-causes-fallback", "insecure", {"Connection": "X-Custom-Ip", "X-Custom-Ip": "198.51.100.2", "X-Real-Ip": "invalid"},
                          lambda a: "X-Custom-Ip" not in before(a)["Headers"] and head(a)["x-v0-selected"] == "peer" and head(a)["x-real-ip"] == "127.0.0.1")
                    check("connection-allowlist-identity", "allowed", {"Connection": "X-Custom-Ip", "X-Custom-Ip": "198.51.100.2"},
                          lambda a: before(a)["Headers"]["X-Custom-Ip"] == ["198.51.100.2"] and head(a)["x-v0-selected"] == "X-Custom-Ip" and "x-custom-ip" not in head(a))
                    check("connection-removes-selector", "selector", {"Connection": "X-Zone", "X-Zone": "yes", "X-Custom-Ip": "198.51.100.2"},
                          lambda a: "X-Zone" not in before(a)["Headers"] and head(a)["x-v0-selected"] == "X-Real-Ip")
                    check("connection-allowlist-selector", "selectorallowed", {"Connection": "X-Zone", "X-Zone": "yes", "X-Custom-Ip": "198.51.100.2"},
                          lambda a: before(a)["Headers"]["X-Zone"] == ["yes"] and head(a)["x-v0-selected"] == "X-Custom-Ip" and "x-zone" not in head(a))
                    check("peer-fallback", "insecure", {"X-Real-Ip": "invalid"},
                          lambda a: head(a)["x-v0-selected"] == "peer" and head(a)["x-real-ip"] == "127.0.0.1")
                    check("backend-xff", "insecure", {"X-Custom-Ip": "198.51.100.2", "X-Forwarded-For": "203.0.113.99"},
                          lambda a: head(a)["x-forwarded-for"] == "198.51.100.2")
                    check("unmatched", "insecure", {"X-Real-Ip": "203.0.113.99"}, lambda a: a["status"] == 404, "/unmatched")
                    check("root-sees-peer", "insecure", {"X-Custom-Ip": "198.51.100.2"}, lambda a: a["status"] == 200, "/root-peer")
                    check("root-not-effective", "insecure", {"X-Custom-Ip": "198.51.100.2"}, lambda a: a["status"] == 404, "/root-effective")
                    check("child-sees-effective", "insecure", {"X-Custom-Ip": "198.51.100.2"}, lambda a: a["status"] == 200 and head(a)["x-real-ip"] == "198.51.100.2" and before(a)["Peer"].startswith("127.0.0.1:"), "/parent/child")
                    check("child-default-404", "insecure", {"X-Custom-Ip": "198.51.100.2"}, lambda a: a["status"] == 404, "/parent/missing")
                    check("encoded-path-rejected", "insecure", {"X-Custom-Ip": "198.51.100.2"}, lambda a: a["status"] == 400, "/covered/a%2fb")
                    check("internal-ping", "insecure", {"X-Custom-Ip": "198.51.100.2"}, lambda a: a["status"] == 200, "/ping")
                    def raw_case(name, entry, prefix, tls=False, host="a.example"):
                        sock = socket.create_connection(("127.0.0.1", ports[entry]), timeout=3)
                        if tls:
                            context = ssl._create_unverified_context()
                            sock = context.wrap_socket(sock, server_hostname="a.example")
                        sock.sendall(prefix + (f"GET /covered/{name} HTTP/1.1\r\nHost: {host}\r\nX-Real-Ip: invalid\r\nConnection: close\r\n\r\n").encode())
                        response = http.client.HTTPResponse(sock)
                        response.begin()
                        body = response.read().decode()
                        status = response.status
                        sock.close()
                        actual = {"status": status, "response": json.loads(body) if status == 200 else body}
                        if name == "proxy-zero":
                            passed = status == 200 and before(actual)["Peer"] == "0.0.0.0:0" and head(actual)["x-real-ip"] == "0.0.0.0"
                        elif name == "proxy-local":
                            passed = status == 200 and before(actual)["Peer"].startswith("127.0.0.1:")
                        elif name == "tls-state":
                            passed = status == 200 and before(actual)["TLS"] and head(actual)["x-v0-tls-preserved"] == "true" and before(actual)["Headers"]["X-Forwarded-Proto"] == ["https"]
                        else:
                            passed = status == 421
                        results.append({"case": name, "passed": passed, **actual})
                        (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
                        print(("PASS " if passed else "CONTRADICTION ") + name, flush=True)
                        if not passed:
                            raise AssertionError(name)
                    raw_case("proxy-zero", "proxy", b"PROXY TCP4 0.0.0.0 127.0.0.1 0 80\r\n")
                    raw_case("proxy-local", "proxy", b"\r\n\r\n\0\r\nQUIT\n" + bytes([0x20, 0, 0, 0]))
                    raw_case("tls-state", "tls", b"", tls=True)
                    raw_case("sni-rejection", "tls", b"", tls=True, host="b.example")
                    conn = http.client.HTTPConnection("127.0.0.1", ports["insecure"], timeout=3)
                    conn.request("GET", "/covered/stream-http1", headers={"X-Custom-Ip": "198.51.100.2"})
                    response = conn.getresponse()
                    first = response.readline()
                    release = http.client.HTTPConnection("127.0.0.1", backend.server_port, timeout=3)
                    release.request("GET", "/release")
                    release.getresponse().read()
                    release.close()
                    second = response.readline()
                    passed = first == b"first\n" and second == b"second\n" and response.getheader("X-V0-Effective") == "198.51.100.2"
                    conn.close()
                    results.append({"case": "http1-streaming", "passed": passed, "firstBeforeRelease": first.decode(), "second": second.decode()})
                    if not passed:
                        raise AssertionError("http1-streaming")
                    completed = subprocess.run([str(root / "http2-client"), f"https://127.0.0.1:{ports['tls']}/covered/stream-http2", f"http://127.0.0.1:{backend.server_port}/release"], check=True, capture_output=True, text=True)
                    h2 = json.loads(completed.stdout)
                    passed = h2["effective"] == "198.51.100.2"
                    results.append({"case": "http2-streaming", "passed": passed, "observation": h2})
                    if not passed:
                        raise AssertionError("http2-streaming")
                    ws = socket.create_connection(("127.0.0.1", ports["insecure"]), timeout=3)
                    ws.sendall(b"GET /covered/websocket HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nX-Custom-Ip: 198.51.100.2\r\n\r\n")
                    ws_response = http.client.HTTPResponse(ws)
                    ws_response.begin()
                    payload = b"v0-stream"
                    mask = b"abcd"
                    ws.sendall(bytes([0x81, 0x80 | len(payload)]) + mask + bytes(value ^ mask[i % 4] for i, value in enumerate(payload)))
                    echoed = ws_response.fp.read(2 + len(payload))
                    passed = ws_response.status == 101 and ws_response.getheader("X-V0-Effective") == "198.51.100.2" and echoed == bytes([0x81, len(payload)]) + payload
                    ws_response.close()
                    ws.close()
                    results.append({"case": "websocket-handshake-data", "passed": passed, "status": 101, "echo": echoed.hex()})
                    (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
                    if not passed:
                        raise AssertionError("websocket-handshake-data")
                    print("PASS HTTP/1.1 and HTTP/2 streaming; WebSocket handshake/data", flush=True)


                finally:
                    proc.terminate()
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
            records = [json.loads(line) for line in (output / "access.jsonl").read_text().splitlines()]
            by_path = {r["RequestPath"]: r for r in records}
            checks = {
                "log-mutated-header-original-core": by_path["/covered/backend-xff"].get("request_X-Real-Ip") == "198.51.100.2" and by_path["/covered/backend-xff"].get("ClientHost") == "203.0.113.99" and by_path["/covered/backend-xff"].get("ClientAddr", "").startswith("127.0.0.1:") and "request_X-Forwarded-For" not in by_path["/covered/backend-xff"],
                "log-entrypoint-field": all(r.get("entryPointName") in ports for r in records),
                "child-404-ran-default": by_path["/parent/missing"].get("request_X-V0-Selected") == "X-Custom-Ip",
                "unmatched-did-not-run": "request_X-V0-Selected" not in by_path["/unmatched"] and "RouterName" not in by_path["/unmatched"],
                "internal-ran-default": by_path["/ping"].get("request_X-V0-Selected") == "X-Custom-Ip",
                "encoded-rejection-before-plugin": "request_X-V0-Selected" not in by_path["/covered/a%2Fb"],
                "sni-rejection-before-plugin": "request_X-V0-Selected" not in by_path["/covered/sni-rejection"],
            }
            for name, passed in checks.items():
                results.append({"case": name, "passed": passed})
                (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
                print(("PASS " if passed else "CONTRADICTION ") + name, flush=True)
                if not passed:
                    raise AssertionError(name)
    finally:
        backend.shutdown()
        backend.server_close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--traefik", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    run(str(pathlib.Path(args.traefik).resolve()), args.output.resolve())
