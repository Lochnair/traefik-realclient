#!/usr/bin/env python3
"""V1 streaming suite: native HTTP/2, WebSocket data and native gRPC bidi
streaming through Traefik 3.7.12 + the real plugin (§9)."""
import argparse
import http.client
import json
import pathlib
import socket
import subprocess
import tempfile

import harness

HERE = pathlib.Path(__file__).resolve().parent


def build_static(root, backend_port, grpc_backend_port, ports, cert, key):
    source = {
        "name": "edge",
        "trust": {"static": ["127.0.0.1/32"]},
        "extract": {"header": "X-Real-Ip", "mode": "single"},
        "scheme": {"header": "X-Forwarded-Proto", "mode": "single"},
    }
    dynamic = {
        "http": {
            "routers": {
                "ws": {"rule": "PathPrefix(`/`)", "entryPoints": ["ws"], "service": "echo"},
                "h2": {"rule": "Host(`origin.test`) && PathPrefix(`/stream`)", "entryPoints": ["h2"],
                       "service": "echo", "tls": {}},
                "grpc": {"rule": "Host(`origin.test`) && PathPrefix(`/probe.`)", "entryPoints": ["h2"],
                         "service": "grpc", "tls": {}},
            },
            "middlewares": {"realclient": {"plugin": {"realclient": {"sources": [source]}}}},
            "services": {
                "echo": {"loadBalancer": {"servers": [{"url": f"http://127.0.0.1:{backend_port}"}]}},
                "grpc": {"loadBalancer": {"servers": [{"url": f"h2c://127.0.0.1:{grpc_backend_port}"}]}},
            },
        },
        "tls": {"certificates": [{"certFile": cert, "keyFile": key}]},
    }
    (root / "dynamic.yml").write_text(json.dumps(dynamic))
    return {
        "entryPoints": {
            "ws": {"address": f"127.0.0.1:{ports['ws']}", "forwardedHeaders": {"insecure": True},
                   "http": {"middlewares": ["realclient@file"]}},
            "h2": {"address": f"127.0.0.1:{ports['h2']}", "forwardedHeaders": {"insecure": True},
                   "http": {"middlewares": ["realclient@file"]}},
        },
        "providers": {"file": {"filename": str(root / "dynamic.yml")}},
        "experimental": {"localPlugins": {"realclient": {"moduleName": harness.MODULE}}},
        "log": {"level": "INFO"},
        "global": {"checkNewVersion": False, "sendAnonymousUsage": False},
        "ping": {"entryPoint": "ws"},
    }


def run(binary, output):
    output.mkdir(parents=True, exist_ok=True)
    results = harness.Results(output / "results.json")
    backend = harness.start_backend()
    grpc_backend_port = harness.freeport()
    grpcproc = None
    try:
        with tempfile.TemporaryDirectory(prefix="realclient-v1-stream-") as tmp:
            root = pathlib.Path(tmp)
            harness.stage_plugin(root)
            cert, key = harness.self_signed(root)
            ports = {n: harness.freeport() for n in ["ws", "h2"]}

            h2bin = root / "http2probe"
            subprocess.run(["go", "build", "-o", str(h2bin), "."], cwd=HERE / "http2probe", check=True)
            grpcbin = root / "grpcprobe"
            subprocess.run(["go", "build", "-o", str(grpcbin), "."], cwd=HERE / "grpcprobe", check=True)

            static = build_static(root, backend.server_port, grpc_backend_port, ports, cert, key)
            ready = f"http://127.0.0.1:{ports['ws']}/__up"
            with harness.traefik(binary, root, static, output, ready):
                W, H = ports["ws"], ports["h2"]

                # 1. WebSocket handshake + masked client frame echo through the plugin.
                ws = socket.create_connection(("127.0.0.1", W), timeout=5)
                ws.sendall(
                    b"GET /socket HTTP/1.1\r\nHost: origin.test\r\nConnection: Upgrade\r\n"
                    b"Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
                    b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                    b"X-Real-Ip: 198.51.100.91\r\n\r\n")
                resp = http.client.HTTPResponse(ws)
                resp.begin()
                payload = b"realclient-ws"
                mask = b"wxyz"
                ws.sendall(bytes([0x81, 0x80 | len(payload)]) + mask
                           + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))
                echoed = resp.fp.read(2 + len(payload))
                ok = (resp.status == 101
                      and resp.getheader("X-Effective") == "198.51.100.91"
                      and resp.getheader("X-Proto") in ("wss", "ws")
                      and echoed == bytes([0x81, len(payload)]) + payload)
                results.record("websocket-handshake-data", ok, status=resp.status,
                               effective=resp.getheader("X-Effective"),
                               proto=resp.getheader("X-Proto"), echo=echoed.hex())
                ws.close()

                # 2. native HTTP/2 response streaming with resolved identity.
                out = subprocess.run(
                    [str(h2bin), f"https://127.0.0.1:{H}/stream", f"http://127.0.0.1:{backend.server_port}/__release",
                     "origin.test"], capture_output=True, text=True, timeout=30)
                h2 = json.loads(out.stdout or "{}")
                results.record("http2-streaming",
                               out.returncode == 0 and h2.get("proto", "").startswith("HTTP/2")
                               and h2.get("first") == "first\n" and h2.get("second") == "second\n"
                               and h2.get("effective") == "198.51.100.90",
                               observation=h2, stderr=out.stderr[-400:])

                # 3. native gRPC bidirectional streaming with resolved identity + trailers.
                out = subprocess.run(
                    [str(grpcbin), f"127.0.0.1:{H}", f"127.0.0.1:{grpc_backend_port}", "origin.test"],
                    capture_output=True, text=True, timeout=40)
                g = json.loads(out.stdout or "{}")
                results.record("grpc-bidi-streaming",
                               out.returncode == 0
                               and g.get("echoes") == ["echo:one", "echo:two", "echo:three"]
                               and g.get("observed_real_ip") == "198.51.100.77"
                               and g.get("observed_proto") == "https"
                               and g.get("grpc_status_ok") is True,
                               observation=g, stderr=out.stderr[-400:])
        return results.finish()
    finally:
        if grpcproc:
            grpcproc.terminate()
        backend.shutdown()
        backend.server_close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--traefik", required=True)
    ap.add_argument("--output", type=pathlib.Path, required=True)
    a = ap.parse_args()
    raise SystemExit(run(str(pathlib.Path(a.traefik).resolve()), a.output.resolve()))
