import argparse
import os
import re
import time
import requests

# Patterns to capture various failure modes and metadata.
# Example NGINX error lines (OpenSSL/OQS variants may differ slightly):
# 2024/09/03 10:51:22 [info] 6#6: *3 SSL_do_handshake() failed (SSL: error:0A000126:SSL routines::unexpected eof while reading) while SSL handshaking, client: 10.1.2.3:58432, server: example.test
# 2024/09/03 10:51:25 [info] 6#6: *4 SSL_do_handshake() failed (SSL: error:0A00018E:SSL routines::no shared groups) while SSL handshaking, client: 10.1.2.3:58440, server: example.test
# 2024/09/03 10:51:28 [info] 6#6: *5 SSL_do_handshake() failed (SSL: error:0A000152:SSL routines::unsupported group) while SSL handshaking, client: 10.1.2.3:58441, server: example.test

BASE_PATTERN = re.compile(r'.*SSL_do_handshake\(\) failed.*?client:\s*(?P<ipport>[^,]+),.*?server:\s*(?P<sni>\S+).*')
NO_SHARED_GROUPS_RE = re.compile(r'no shared groups', re.IGNORECASE)
UNSUPPORTED_GROUP_RE = re.compile(r'unsupported group', re.IGNORECASE)

def classify_reason(line: str) -> str:
    if NO_SHARED_GROUPS_RE.search(line):
        return "no_shared_groups"
    if UNSUPPORTED_GROUP_RE.search(line):
        return "unsupported_group"
    return "handshake_failure"

def main():
    ap = argparse.ArgumentParser(description="Tail NGINX error log for TLS handshake failures and emit deny events")
    ap.add_argument("--error-log", required=True)
    ap.add_argument("--events-url", required=True, help="Control plane /events endpoint (http://host:port/events)")
    ap.add_argument("--policy-id", default="default-pqc-policy")
    ap.add_argument(
        "--allowed-groups",
        default=os.environ.get("ALLOWED_GROUPS", "X25519Kyber768:X25519:P-256"),
    )
    args = ap.parse_args()

    # naive tail -f
    with open(args.error_log, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue

            if "SSL_do_handshake() failed" in line:
                m = BASE_PATTERN.match(line)
                ip = port = None
                if m:
                    ipport = m.group("ipport")
                    if ipport and ":" in ipport:
                        ip, port = ipport.rsplit(":", 1)
                    else:
                        ip = ipport
                reason = classify_reason(line)
                payload = {
                    "kind": "pqc.enforcement",
                    "ts_ms": int(time.time() * 1000),
                    "policy_version": args.policy_id,
                    "policy_hash_b64": "",  # unknown; control plane will recompute
                    "negotiated": {
                        "tls_version": "TLS1.3",
                        "cipher": None,
                        "group_or_kem": None,  # group not known on failure line
                        "sig_alg": None,
                        "sni": m.group("sni") if m else None,
                        "peer_ip": ip,
                        "peer_port": port,
                        "alpn": None,  # ALPN not surfaced in NGINX error line; left None
                        "client_cert_sha256": None,
                        "client_cert_sig_alg": None,
                    },
                    "decision": {"allow": False, "reason": reason},
                }
                try:
                    requests.post(args.events_url, json=payload, timeout=2.0)
                except Exception:
                    # swallow to keep tailer alive
                    pass

if __name__ == "__main__":  # pragma: no cover
    main()
