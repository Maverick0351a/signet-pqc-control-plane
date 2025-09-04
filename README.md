
# Signet PQC Control Plane (MVP)

**Goal:** prove the closed loop for PQC migration — **Policy → Enforcement → Cryptographic Proof** — using tools and practices consistent with the Signet work (canonical receipts, hash-linking, Merkle STH, CLI verification).

This repo ships a tiny control plane (FastAPI) plus receipt libraries and tests. The actual TLS enforcement is abstracted for the MVP; you can plug in a TLS terminator (e.g., OpenSSL 3 + OQS provider) later and feed handshake telemetry into `pqc.enforcement` receipts.

## What’s included

- **`spcp.receipts`** – Canonicalization, Ed25519 signing/verify, Merkle STH + inclusion proofs, compliance pack bundling.
- **`spcp.api`** – Minimal policy service (`GET/PUT /policy`) and receipt intake (`POST /events`) that stores hash-linked receipts.
- **`spcp.policy.circuit_breaker`** – Simple error-rate based rollback that emits a `policy.change` receipt.
- **Schemas** – JSON schemas for:
  - `pqc.enforcement`
  - `pqc.cbom`
  - `policy.change`

> **Note:** Canonicalization uses a deterministic JSON encoding (sorted keys, minimal separators). For strict RFC 8785 JCS equivalence, swap in a proven JCS implementation later. The receipts are designed to avoid floats to keep canonicalization stable.

## Quick start

```bash
# Install (editable)
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# Run tests
pytest

# Run API
uvicorn spcp.api.main:app --reload
```

## Endpoints

- `GET /policy` → current policy JSON
- `PUT /policy` → set policy (versioned); returns `policy.change` receipt
- `POST /events` → submit a receipt (e.g., `pqc.enforcement` or `pqc.cbom`); API validates, hash-links, stores, and updates STH

Receipts & STH are written under `./data` by default (override via `SPCP_DATA_DIR`).

## Wiring an enforcement proxy

For the MVP: your proxy (or a script shimming `openssl s_server` logs) should POST a `pqc.enforcement` receipt for each handshake with:
- negotiated parameters (tls version, cipher, group/kem, sigalg)
- policy decision (allow/deny) and reason
- a hash-link to prev receipt (control plane will also link on ingest)

See `tests/test_api.py::test_enforcement_flow()` for a working pattern.

## Compliance Pack

Use the `spcp.receipts.pack` helpers (or wire into your CLI) to bundle receipts + STH + a tiny verifier script into a ZIP an auditor can run offline.

## Supply-chain hardening

- `dependabot.yml`, `SECURITY.md`, CI with code quality & tests configured with **least-privilege token permissions**.
- You should **pin GitHub Actions by full commit SHA** using your existing pinning script before enabling required checks.

## License

Apache-2.0
