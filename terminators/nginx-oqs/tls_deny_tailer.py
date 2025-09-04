import argparse
import datetime
import json
import os
import re
import time
import requests

PATTERN = re.compile(r'.*SSL_do_handshake\(\) failed.*?client:\s*(?P<ip>[^,]+),.*?server:\s*(?P<sni>\S+).*')

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
                m = PATTERN.match(line)
                payload = {
                    "kind": "pqc.enforcement",
                    # Backwards compatible with existing receipt model expectations
                    "ts_ms": int(time.time() * 1000),
                    "policy_version": args.policy_id,
                    "policy_hash_b64": "",  # unknown in sidecar; control plane may ignore
                    "negotiated": {
                        "tls_version": "TLS1.3",
                        "cipher": None,
                        "group_or_kem": None,
                        "sig_alg": None,
                        "sni": m.group("sni") if m else None,
                        "peer_ip": m.group("ip") if m else None,
                    },
                    "decision": {"allow": False, "reason": "handshake_failure"},
                }
                try:
                    requests.post(args.events_url, json=payload, timeout=2.0)
                except Exception:
                    # swallow to keep tailer alive
                    pass

if __name__ == "__main__":  # pragma: no cover
    main()
