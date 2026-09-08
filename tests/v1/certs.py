#!/usr/bin/env python3
"""V1 certificate-path integrations (§9): mtlswhitelist certificate branch and
its separate no-certificate IP-range branch, plus Traefik's built-in
passTLSClientCert running after Realclient (forged assertions cleared, the real
req.TLS state republished downstream)."""
import argparse
import http.client
import json
import pathlib
import socket
import ssl
import subprocess
import tempfile

import harness

MTLS_MODULE = "github.com/smerschjohann/mtlswhitelist"
MTLS_REPO = "smerschjohann/mtlswhitelist"
MTLS_REF = "v0.3.0"


def openssl(*args):
    subprocess.run(["openssl", *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def pki(root):
    ca_key, ca = root / "ca.key", root / "ca.pem"
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key), "-out", str(ca),
            "-days", "1", "-subj", "/CN=realclient-test-ca")

    def leaf(name, cn, server):
        key, csr, crt, ext = (root / f"{name}.{s}" for s in ("key", "csr", "pem", "ext"))
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", "/CN=" + cn)
        ext.write_text("subjectAltName=DNS:wl.test,DNS:pct.test\nextendedKeyUsage=serverAuth\n"
                       if server else "extendedKeyUsage=clientAuth\n")
        openssl("x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key), "-CAcreateserial",
                "-out", str(crt), "-days", "1", "-extfile", str(ext))
        return str(crt), str(key)

    return str(ca), leaf("server", "wl.test", True), leaf("client", "client-alpha", False)


def mtls_req(port, path, host, client=None, headers=None):
    ctx = ssl._create_unverified_context()
    if client:
        ctx.load_cert_chain(client[0], client[1])
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock = ctx.wrap_socket(raw, server_hostname=host)
    hdrs = {"Host": host, "Connection": "close", **(headers or {})}
    sock.sendall((f"GET {path} HTTP/1.1\r\n"
                  + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n").encode())
    resp = http.client.HTTPResponse(sock)
    resp.begin()
    body = resp.read().decode()
    status = resp.status
    sock.close()
    return status, body


def obs(body):
    return {k.lower(): v for k, v in json.loads(body)["headers"].items()}


def run(binary, output):
    output.mkdir(parents=True, exist_ok=True)
    results = harness.Results(output / "results.json")
    backend = harness.start_backend()
    try:
        with tempfile.TemporaryDirectory(prefix="realclient-v1-certs-") as tmp:
            root = pathlib.Path(tmp)
            harness.stage_plugin(root)
            harness.stage_local_plugin(root, MTLS_MODULE, MTLS_REPO, MTLS_REF)
            ca, (server_crt, server_key), client = pki(root)
            port = harness.freeport()

            rc = {"name": "edge", "trust": {"static": ["127.0.0.1/32"]},
                  "extract": {"header": "X-Real-Ip", "mode": "single"}}
            wl = {"rules": [{"type": "ipRange", "ranges": ["198.51.100.0/24"]}],
                  "rejectMessage": {"message": "Forbidden", "code": 403}}
            pct = {"pem": True, "info": {"subject": {"commonName": True}}}
            dynamic = {"http": {
                "routers": {
                    "whitelist": {"rule": "Host(`wl.test`)", "entryPoints": ["mtls"], "service": "echo",
                                  "middlewares": ["realclient", "mtlswhitelist"], "tls": {"options": "mtls"}},
                    "pct": {"rule": "Host(`pct.test`)", "entryPoints": ["mtls"], "service": "echo",
                            "middlewares": ["realclient", "passtls"], "tls": {"options": "mtls"}},
                },
                "middlewares": {
                    "realclient": {"plugin": {"realclient": {"sources": [rc]}}},
                    "mtlswhitelist": {"plugin": {"mtlswhitelist": wl}},
                    "passtls": {"passTLSClientCert": pct},
                },
                "services": {"echo": {"loadBalancer": {"servers": [{"url": f"http://127.0.0.1:{backend.server_port}"}]}}},
            }, "tls": {
                "certificates": [{"certFile": server_crt, "keyFile": server_key}],
                "options": {"mtls": {"clientAuth": {"caFiles": [ca], "clientAuthType": "VerifyClientCertIfGiven"}}},
            }}
            (root / "dynamic.yml").write_text(json.dumps(dynamic))
            static = {
                "entryPoints": {"mtls": {"address": f"127.0.0.1:{port}",
                                         "forwardedHeaders": {"insecure": True},
                                         "http": {"aliasHeadersStrategy": "delete"}}},
                "providers": {"file": {"filename": str(root / "dynamic.yml")}},
                "experimental": {"localPlugins": {
                    "realclient": {"moduleName": harness.MODULE},
                    "mtlswhitelist": {"moduleName": MTLS_MODULE}}},
                "log": {"level": "INFO"},
                "global": {"checkNewVersion": False, "sendAnonymousUsage": False},
            }

            def ready():
                try:
                    return mtls_req(port, "/__up", "wl.test", headers={"X-Real-Ip": "203.0.113.1"})[0] in (200, 403)
                except OSError:
                    return False

            with harness.traefik(binary, root, static, output, ready):
                # 1. no cert, resolved X-Real-Ip inside the range -> allowed.
                st, body = mtls_req(port, "/x", "wl.test", headers={"X-Real-Ip": "198.51.100.42"})
                h = obs(body) if st == 200 else {}
                results.record("mtlswhitelist-ip-range-allow",
                               st == 200 and h.get("x-real-ip") == ["198.51.100.42"], status=st)

                # 2. no cert, resolved X-Real-Ip outside the range -> rejected.
                results.record("mtlswhitelist-ip-range-deny",
                               mtls_req(port, "/x", "wl.test", headers={"X-Real-Ip": "203.0.113.9"})[0] == 403)

                # 3. no cert, forged in-range XFF but the peer resolves out of range:
                #    the canonical X-Real-Ip, not the forged XFF, drives the rule.
                results.record("mtlswhitelist-uses-canonical-not-forged-xff",
                               mtls_req(port, "/x", "wl.test",
                                        headers={"X-Real-Ip": "bogus", "X-Forwarded-For": "198.51.100.7"})[0] == 403)

                # 4. valid client cert, IP out of range -> cert branch allows, proving
                #    Realclient left req.TLS.PeerCertificates intact.
                st, body = mtls_req(port, "/x", "wl.test", client=client, headers={"X-Real-Ip": "203.0.113.9"})
                h = obs(body) if st == 200 else {}
                results.record("mtlswhitelist-certificate-branch",
                               st == 200 and h.get("x-whitelist-cert-cn") == ["client-alpha"],
                               status=st, cn=h.get("x-whitelist-cert-cn"))

                # 5. passTLSClientCert after Realclient: forged assertion cleared,
                #    real cert republished from req.TLS.
                st, body = mtls_req(port, "/x", "pct.test", client=client, headers={
                    "X-Real-Ip": "198.51.100.42",
                    "X-Forwarded-Tls-Client-Cert": "FORGEDCERT",
                    "X-Forwarded-Tls-Client-Cert-Info": "FORGEDINFO"})
                h = obs(body)
                cert = (h.get("x-forwarded-tls-client-cert") or [""])[0]
                info = (h.get("x-forwarded-tls-client-cert-info") or [""])[0]
                results.record("passtls-forged-cleared-real-republished",
                               st == 200 and "FORGED" not in cert and "FORGED" not in info
                               and "MII" in cert and "client-alpha" in info,
                               cert_prefix=cert[:16], info=info[:80])

                # 6. passTLSClientCert with no client cert: forged assertion still gone.
                st, body = mtls_req(port, "/x", "pct.test", headers={
                    "X-Real-Ip": "198.51.100.42", "X-Forwarded-Tls-Client-Cert": "FORGEDCERT"})
                h = obs(body)
                results.record("passtls-no-cert-forged-cleared",
                               st == 200 and "FORGED" not in (h.get("x-forwarded-tls-client-cert") or [""])[0],
                               value=h.get("x-forwarded-tls-client-cert"))
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
