#!/usr/bin/env python3
"""V1 core runtime suite: the real plugin through Traefik 3.7.12 / Yaegi 0.16.1.

Covers §9 items that need no external plugin: Yaegi load, secure/insecure
forwarded-header handling, entrypoint-default placement and early rejection,
backend-observed canonical identity/forwarding headers, Traefik's real XFF
append + instance joining, aliasHeadersStrategy: delete, IPv4/IPv6/mapped
paths, X-Forwarded-Server preservation, scheme aliases, the HTTP-over-TLS-origin
forwarded-port difference vs stock Traefik, delegated XFCC preservation, and
HTTP/1.1 response streaming.
"""
import argparse
import http.client
import json
import pathlib
import socket
import ssl
import tempfile

import harness


def build_static(root, backend_port, ports, cert, key):
    def ep(name, secure):
        fwd = {"insecure": not secure}
        cfg = {"address": f"127.0.0.1:{ports[name]}", "forwardedHeaders": fwd,
               "http": {"aliasHeadersStrategy": "delete"}}
        if name != "stock":
            cfg["http"]["middlewares"] = ["realclient@file"]
        return cfg

    entrypoints = {
        "plugin": ep("plugin", secure=False),
        "secure": ep("secure", secure=True),
        "stock": ep("stock", secure=False),
        "tls": ep("tls", secure=False),
        "place": ep("place", secure=False),
        "multi": ep("multi", secure=False),
    }
    entrypoints["multi"]["http"]["middlewares"] = ["realclient-multi@file"]
    entrypoints["place"]["http"]["encodedCharacters"] = {"allowEncodedSlash": False}
    source = {
        "name": "edge",
        "trust": {"static": ["127.0.0.1/32"]},
        "extract": {"header": "X-Real-Ip", "mode": "single"},
        "scheme": {"header": "X-Forwarded-Proto", "mode": "single"},
    }
    # Two-source instance: a header-selected source that usually does not match,
    # ahead of the broad edge source, to exercise cross-source input deletion.
    multi = [
        {"name": "zoned", "trust": {"static": ["127.0.0.1/32"],
                                    "headerIn": {"name": "X-Zone", "values": ["z1"]}},
         "extract": {"header": "X-Zone-Client", "mode": "single"}},
        source,
    ]
    dynamic = {
        "http": {
            "routers": {
                "plugin": {"rule": "PathPrefix(`/`)", "entryPoints": ["plugin"], "service": "echo"},
                "multi": {"rule": "PathPrefix(`/`)", "entryPoints": ["multi"], "service": "echo"},
                "secure": {"rule": "PathPrefix(`/`)", "entryPoints": ["secure"], "service": "echo"},
                "stock": {"rule": "PathPrefix(`/`)", "entryPoints": ["stock"], "service": "echo"},
                "tls": {"rule": "Host(`origin.test`)", "entryPoints": ["tls"], "service": "echo",
                        "tls": {}},
                "root-peer": {"rule": "Path(`/root-peer`) && ClientIP(`127.0.0.1/32`)",
                              "entryPoints": ["place"], "service": "echo"},
                "root-effective": {"rule": "Path(`/root-effective`) && ClientIP(`198.51.100.2/32`)",
                                   "entryPoints": ["place"], "service": "echo"},
                "parent": {"rule": "PathPrefix(`/parent`)", "entryPoints": ["place"]},
                "child": {"rule": "Path(`/parent/child`) && ClientIP(`198.51.100.2/32`)",
                          "parentRefs": ["parent"], "service": "echo"},
            },
            "middlewares": {
                "realclient": {"plugin": {"realclient": {"sources": [source]}}},
                "realclient-multi": {"plugin": {"realclient": {"sources": multi}}},
            },
            "services": {"echo": {"loadBalancer": {"servers": [{"url": f"http://127.0.0.1:{backend_port}"}]}}},
        },
        "tls": {"certificates": [{"certFile": cert, "keyFile": key}]},
    }
    (root / "dynamic.yml").write_text(json.dumps(dynamic))
    return {
        "entryPoints": entrypoints,
        "providers": {"file": {"filename": str(root / "dynamic.yml")}},
        "experimental": {"localPlugins": {"realclient": {"moduleName": harness.MODULE}}},
        "log": {"level": "INFO"},
        "global": {"checkNewVersion": False, "sendAnonymousUsage": False},
        "ping": {"entryPoint": "plugin"},
        "accessLog": {"addInternals": True, "format": "json", "filePath": str(root / "access.jsonl"),
                      "bufferingSize": 10, "fields": {"headers": {"defaultMode": "keep"}}},
    }


def req(port, path, headers, host=None, method="GET"):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    if host:
        headers = {**headers, "Host": host}
    conn.request(method, path, headers=headers)
    r = conn.getresponse()
    body = r.read().decode()
    out = (r.status, dict(r.getheaders()), body)
    conn.close()
    return out


def tls_req(port, path, headers, server_name="origin.test"):
    ctx = ssl._create_unverified_context()
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock = ctx.wrap_socket(raw, server_hostname=server_name)
    hdr = "".join(f"{k}: {v}\r\n" for k, v in {**headers, "Host": server_name, "Connection": "close"}.items())
    sock.sendall(f"GET {path} HTTP/1.1\r\n{hdr}\r\n".encode())
    resp = http.client.HTTPResponse(sock)
    resp.begin()
    body = resp.read().decode()
    status = resp.status
    sock.close()
    return status, body


def observed(body):
    o = json.loads(body)
    o["h"] = {k.lower(): v for k, v in o["headers"].items()}
    return o


def one(h, name):
    v = h.get(name.lower())
    return v[0] if v and len(v) == 1 else None


def run(binary, output):
    output.mkdir(parents=True, exist_ok=True)
    results = harness.Results(output / "results.json")
    backend = harness.start_backend()
    try:
        with tempfile.TemporaryDirectory(prefix="realclient-v1-core-") as tmp:
            root = pathlib.Path(tmp)
            harness.stage_plugin(root)
            cert, key = harness.self_signed(root)
            ports = {n: harness.freeport() for n in ["plugin", "secure", "stock", "tls", "place", "multi"]}
            static = build_static(root, backend.server_port, ports, cert, key)
            ready = f"http://127.0.0.1:{ports['plugin']}/__up"
            with harness.traefik(binary, root, static, output, ready):
                P, S, K = ports["plugin"], ports["secure"], ports["stock"]

                # 1. Yaegi actually loaded and ran the real V1 package.
                st, _, body = req(P, "/hello", {"X-Real-Ip": "198.51.100.7", "X-Forwarded-Proto": "https"})
                o = observed(body)
                results.record("yaegi-loads-real-plugin",
                               st == 200 and one(o["h"], "X-Real-Ip") == "198.51.100.7",
                               status=st, x_real_ip=o["h"].get("x-real-ip"))

                # 2. canonical single identity + Traefik XFF append of the effective host.
                results.record("backend-canonical-identity",
                               one(o["h"], "X-Real-Ip") == "198.51.100.7"
                               and o["h"].get("x-forwarded-for") == ["198.51.100.7"],
                               xff=o["h"].get("x-forwarded-for"))

                # 3. scheme resolved + both aliases rebuilt consistently.
                results.record("scheme-aliases-consistent",
                               one(o["h"], "X-Forwarded-Proto") == "https"
                               and one(o["h"], "X-Forwarded-Scheme") == "https"
                               and one(o["h"], "X-Scheme") == "https",
                               xfp=o["h"].get("x-forwarded-proto"),
                               xfs=o["h"].get("x-forwarded-scheme"), xs=o["h"].get("x-scheme"))

                # 4. authority metadata: explicit port echoed; scheme default when absent.
                st, _, body = req(P, "/hello", {"X-Real-Ip": "198.51.100.7",
                                                "X-Forwarded-Proto": "https"}, host="origin.test:8443")
                explicit_port = observed(body)
                st, _, body = req(P, "/hello", {"X-Real-Ip": "198.51.100.7",
                                                "X-Forwarded-Proto": "https"}, host="origin.test")
                default_port = observed(body)
                results.record("forwarded-host-port",
                               one(explicit_port["h"], "X-Forwarded-Host") == "origin.test:8443"
                               and one(explicit_port["h"], "X-Forwarded-Port") == "8443"
                               and one(default_port["h"], "X-Forwarded-Host") == "origin.test"
                               and one(default_port["h"], "X-Forwarded-Port") == "443",
                               explicit=(default_port["h"].get("x-forwarded-host"),
                                         default_port["h"].get("x-forwarded-port")))

                # 5. secure entrypoint strips forged identity; plugin then sees the peer.
                st, _, body = req(S, "/hello", {"X-Real-Ip": "8.8.8.8", "X-Forwarded-Proto": "https"})
                o = observed(body)
                results.record("secure-strips-forged-identity",
                               one(o["h"], "X-Real-Ip") == "127.0.0.1",
                               x_real_ip=o["h"].get("x-real-ip"))

                # 6. insecure entrypoint preserves the supplied identity for the plugin.
                st, _, body = req(P, "/hello", {"X-Real-Ip": "203.0.113.44"})
                o = observed(body)
                results.record("insecure-preserves-identity",
                               one(o["h"], "X-Real-Ip") == "203.0.113.44", x_real_ip=o["h"].get("x-real-ip"))

                # 7. competing identity channels + underscore aliases are swept.
                st, _, body = req(P, "/hello", {
                    "X-Real-Ip": "203.0.113.44", "X-Forwarded-For": "203.0.113.99",
                    "Cf-Connecting-Ip": "1.2.3.4", "True-Client-Ip": "5.6.7.8",
                    "X-Client-Ip": "9.9.9.9", "Forwarded": "for=1.1.1.1"})
                o = observed(body)
                swept = all(k not in o["h"] for k in
                            ["cf-connecting-ip", "true-client-ip", "x-client-ip", "forwarded"])
                results.record("competing-identity-headers-removed",
                               swept and o["h"].get("x-forwarded-for") == ["203.0.113.44"],
                               leftover=[k for k in o["h"] if k in
                                         ["cf-connecting-ip", "true-client-ip", "x-client-ip", "forwarded"]])

                # 8. multiple inbound XFF instances (Traefik joins them) still collapse
                #    to exactly the effective entry after the plugin deletes + Traefik appends.
                conn = http.client.HTTPConnection("127.0.0.1", P, timeout=5)
                conn.putrequest("GET", "/hello")
                conn.putheader("X-Real-Ip", "203.0.113.44")
                conn.putheader("X-Forwarded-For", "10.0.0.1")
                conn.putheader("X-Forwarded-For", "10.0.0.2, 10.0.0.3")
                conn.endheaders()
                r = conn.getresponse()
                o = observed(r.read().decode())
                conn.close()
                results.record("xff-instances-joined-then-normalized",
                               o["h"].get("x-forwarded-for") == ["203.0.113.44"],
                               xff=o["h"].get("x-forwarded-for"))

                # 9. aliasHeadersStrategy: delete blocks dotted/underscore CGI aliases.
                conn = http.client.HTTPConnection("127.0.0.1", P, timeout=5)
                conn.putrequest("GET", "/hello", skip_host=True)
                conn.putheader("Host", "x")
                conn.putheader("X-Real-Ip", "203.0.113.44")
                conn.putheader("X_Real_Ip", "6.6.6.6")
                conn.endheaders()
                r = conn.getresponse()
                o = observed(r.read().decode())
                conn.close()
                results.record("alias-delete-posture",
                               one(o["h"], "X-Real-Ip") == "203.0.113.44"
                               and "x_real_ip" not in o["h"],
                               keys=[k for k in o["h"] if "real" in k])

                # 10. IPv4 / IPv6 / IPv4-mapped extraction and RemoteAddr tuple.
                for label, sent, want in [
                    ("ipv4", "192.0.2.10", "192.0.2.10"),
                    ("ipv6", "2001:db8::10", "2001:db8::10"),
                    ("mapped", "::ffff:192.0.2.10", "192.0.2.10"),
                ]:
                    st, _, body = req(P, "/hello", {"X-Real-Ip": sent})
                    o = observed(body)
                    results.record("extract-%s" % label,
                                   one(o["h"], "X-Real-Ip") == want, got=o["h"].get("x-real-ip"))

                # 11. X-Forwarded-Server preserved (Traefik synthesizes it); Traefik TLS
                #     cert headers cleared; delegated Envoy/Istio XFCC preserved.
                st, _, body = req(P, "/hello", {
                    "X-Real-Ip": "203.0.113.44",
                    "X-Forwarded-Server": "forged-edge",
                    "X-Forwarded-Tls-Client-Cert": "forged",
                    "X-Forwarded-Tls-Client-Cert-Info": "forged",
                    "X-Forwarded-Client-Cert": "By=spiffe://cluster/ns/default"})
                o = observed(body)
                results.record("x-forwarded-server-preserved",
                               bool(one(o["h"], "X-Forwarded-Server")), value=o["h"].get("x-forwarded-server"))
                results.record("traefik-tls-cert-headers-cleared",
                               "x-forwarded-tls-client-cert" not in o["h"]
                               and "x-forwarded-tls-client-cert-info" not in o["h"],
                               leftover=[k for k in o["h"] if k.startswith("x-forwarded-tls")])
                results.record("delegated-xfcc-preserved",
                               one(o["h"], "X-Forwarded-Client-Cert") == "By=spiffe://cluster/ns/default",
                               value=o["h"].get("x-forwarded-client-cert"))

                # 12. metadata preserved.
                st, _, body = req(P, "/hello", {"X-Real-Ip": "203.0.113.44",
                                                "Cf-Ipcountry": "NO", "Cdn-Pullzoneid": "6498612",
                                                "Cf-Visitor": '{"scheme":"http"}'})
                o = observed(body)
                results.record("provider-metadata-preserved",
                               one(o["h"], "Cf-Ipcountry") == "NO" and one(o["h"], "Cdn-Pullzoneid") == "6498612"
                               and "cf-visitor" not in o["h"],
                               country=o["h"].get("cf-ipcountry"), cf_visitor=o["h"].get("cf-visitor"))

                # 13. placement: root routing sees the peer, child sees the rewrite.
                PL = ports["place"]
                results.record("root-router-sees-peer",
                               req(PL, "/root-peer", {"X-Real-Ip": "198.51.100.2"})[0] == 200)
                results.record("root-router-not-effective",
                               req(PL, "/root-effective", {"X-Real-Ip": "198.51.100.2"})[0] == 404)
                st, _, body = req(PL, "/parent/child", {"X-Real-Ip": "198.51.100.2"})
                results.record("child-router-sees-effective",
                               st == 200 and one(observed(body)["h"], "X-Real-Ip") == "198.51.100.2", status=st)
                results.record("child-default-404-still-runs-plugin",
                               req(PL, "/parent/missing", {"X-Real-Ip": "198.51.100.2"})[0] == 404)
                results.record("entrypoint-unmatched-404",
                               req(PL, "/nothing-here", {"X-Real-Ip": "198.51.100.2"})[0] == 404)

                # 14. early rejections happen before the plugin.
                results.record("encoded-path-rejected",
                               req(PL, "/parent/a%2fb", {"X-Real-Ip": "198.51.100.2"})[0] == 400)

                # 15. peer fallback on a malformed identity: keep the peer, 200 not 500.
                st, _, body = req(P, "/hello", {"X-Real-Ip": "not-an-ip"})
                o = observed(body)
                results.record("malformed-identity-peer-fallback",
                               st == 200 and one(o["h"], "X-Real-Ip") == "127.0.0.1",
                               status=st, got=o["h"].get("x-real-ip"))

                # 16. stock-Traefik forwarding comparison.
                st, _, body = req(K, "/hello", {"X-Real-Ip": "203.0.113.44",
                                                                "X-Forwarded-Proto": "https"})
                stock = observed(body)
                st, _, body = req(P, "/hello", {"X-Real-Ip": "203.0.113.44", "X-Forwarded-Proto": "https"})
                plug = observed(body)
                results.record("stock-comparison-server-identifier",
                               bool(one(stock["h"], "X-Forwarded-Server"))
                               and bool(one(plug["h"], "X-Forwarded-Server")),
                               stock=stock["h"].get("x-forwarded-server"), plugin=plug["h"].get("x-forwarded-server"))
                results.record("stock-comparison-scheme-aliases",
                               one(plug["h"], "X-Forwarded-Scheme") == "https"
                               and one(plug["h"], "X-Scheme") == "https",
                               note="plugin always emits consistent aliases; stock may omit",
                               stock_xfs=stock["h"].get("x-forwarded-scheme"))

                # 17. HTTP-over-TLS-origin forwarded-port difference.
                sp, sbody = tls_req(ports["tls"], "/p", {"X-Real-Ip": "203.0.113.44",
                                                         "X-Forwarded-Proto": "http"})
                plug_tls = observed(sbody)
                sp2, sbody2 = tls_req(ports["tls"], "/p", {"X-Real-Ip": "203.0.113.44",
                                                          "X-Forwarded-Proto": "http"}, server_name="origin.test")
                results.record("http-over-tls-origin-port-is-80",
                               one(plug_tls["h"], "X-Forwarded-Port") == "80"
                               and one(plug_tls["h"], "X-Forwarded-Proto") == "http",
                               port=plug_tls["h"].get("x-forwarded-port"))

                # 18. HTTP/1.1 response streaming with correct identity.
                conn = http.client.HTTPConnection("127.0.0.1", P, timeout=5)
                conn.request("GET", "/stream", headers={"X-Real-Ip": "198.51.100.55"})
                r = conn.getresponse()
                first = r.read(6)
                rel = http.client.HTTPConnection("127.0.0.1", backend.server_port, timeout=5)
                rel.request("GET", "/__release")
                rel.getresponse().read()
                rel.close()
                second = r.read(7)
                results.record("http1-streaming",
                               first == b"first\n" and second == b"second\n"
                               and r.getheader("X-Effective") == "198.51.100.55",
                               first=first.decode(), second=second.decode(),
                               effective=r.getheader("X-Effective"), xff=r.getheader("X-Fwd-For"))
                conn.close()

                # 19. two-source instance: the unselected source's extraction header
                #     is still swept, and a duplicate extraction header is unusable.
                M = ports["multi"]
                st, _, body = req(M, "/hello", {"X-Real-Ip": "198.51.100.61",
                                                "X-Zone-Client": "203.0.113.61"})
                o = observed(body)
                results.record("multi-source-unselected-header-swept",
                               one(o["h"], "X-Real-Ip") == "198.51.100.61" and "x-zone-client" not in o["h"],
                               x_real_ip=o["h"].get("x-real-ip"), leftover=o["h"].get("x-zone-client"))

                st, _, body = req(M, "/hello", {"X-Zone": "z1", "X-Zone-Client": "203.0.113.62",
                                                "X-Real-Ip": "198.51.100.62"})
                o = observed(body)
                results.record("multi-source-header-selected-source-wins",
                               one(o["h"], "X-Real-Ip") == "203.0.113.62" and "x-zone-client" not in o["h"],
                               x_real_ip=o["h"].get("x-real-ip"))

                conn = http.client.HTTPConnection("127.0.0.1", P, timeout=5)
                conn.putrequest("GET", "/hello", skip_host=True)
                conn.putheader("Host", "x")
                conn.putheader("X-Real-Ip", "198.51.100.71")
                conn.putheader("X-Real-Ip", "198.51.100.72")
                conn.endheaders()
                r2 = conn.getresponse()
                o = observed(r2.read().decode())
                conn.close()
                results.record("duplicate-extraction-header-peer-fallback",
                               one(o["h"], "X-Real-Ip") == "127.0.0.1", got=o["h"].get("x-real-ip"))
        return results.finish()
    finally:
        backend.shutdown()
        backend.server_close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--traefik", required=True)
    ap.add_argument("--output", type=pathlib.Path, required=True)
    a = ap.parse_args()
    raise SystemExit(run(str(pathlib.Path(a.traefik).resolve()), a.output.resolve()))
