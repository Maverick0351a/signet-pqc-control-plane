#!/usr/bin/env python3
"""Tail NGINX access log capturing negotiated TLS/PQC tuple and emit receipts.

MVP logic:
  * Parse structured log_format 'handshake' lines (key="value" pairs).
  * Derive negotiated tuple (protocol, cipher, group) -> post pqc.enforcement allow receipt.
  * Optional: future policy enforcement hook (invoke control plane policy endpoint to fetch deny list).

Assumptions:
  * Control plane API reachable at http://app:8000
  * Signing & chain handled server-side; we only submit event skeleton.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Dict

import requests

LOG_PATH = Path(os.environ.get("HANDSHAKE_LOG", "/var/log/nginx/handshake.log"))
CONTROL_PLANE = os.environ.get("CONTROL_PLANE_URL", "http://app:8000")
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "1.0"))

LINE_RE = re.compile(r'(\w+)="([^"]*)"')


def parse_line(line: str) -> Dict[str, str]:
    return {k: v for k, v in LINE_RE.findall(line)}


def build_event(fields: Dict[str, str]) -> dict:
    negotiated = {
        "tls_version": fields.get("proto"),
        "cipher": fields.get("cipher"),
        "group_or_kem": fields.get("group"),
        "sig_alg": "ed25519",  # placeholder until upstream extraction
        "sni": fields.get("sni"),
        "peer_ip": fields.get("ip"),
        "alpn": fields.get("alpn"),
        "client_cert_sha256": None,
        "client_cert_sig_alg": None,
    }
    return {
        "kind": "pqc.enforcement",
        "ts_ms": int(time.time() * 1000),
        "policy_version": "v0",  # control plane will replace if needed
        "policy_hash_b64": "",
        "negotiated": negotiated,
        "decision": {"allow": True},
    }


def post_event(evt: dict) -> None:
    try:
        r = requests.post(f"{CONTROL_PLANE}/events", json=evt, timeout=3)
        if r.status_code >= 300:
            print(f"Post failed {r.status_code}: {r.text[:200]}")
    except Exception as e:  # noqa: S112
        print(f"Post error: {e}")


def tail_loop():
    # Simple seek to end then follow new lines
    if not LOG_PATH.exists():
        print(f"Log not found: {LOG_PATH}")
        return
    with LOG_PATH.open("r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, 2)
        while True:
            pos = f.tell()
            line = f.readline()
            if not line:
                time.sleep(POLL_INTERVAL)
                f.seek(pos)
                continue
            fields = parse_line(line)
            if not fields:
                continue
            evt = build_event(fields)
            post_event(evt)


if __name__ == "__main__":  # pragma: no cover
    tail_loop()
