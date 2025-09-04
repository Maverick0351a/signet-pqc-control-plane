
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

> **Note (Canonicalization):** As of PR #2 the project implements RFC 8785 (JCS) canonicalization. Older receipts (produced prior to that change) were created with a simpler sorted-key JSON encoder. If you have persisted historical receipts, run:
> `python scripts/receipt_audit.py` (from the repo root) to see whether stored `payload_hash_b64` values match the new JCS hash. If `migration_needed=true` you must preserve legacy verification by either:
> 1. Recomputing and re-signing receipts with JCS (not usually desirable), or
> 2. Keeping a fallback legacy verifier that uses the old sorted-key algorithm for pre-migration timestamps.
> For a fresh deployment (no existing receipts) no action is required.

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


- `dependabot.yml`, `SECURITY.md`, CI with code quality & tests configured with **least-privilege token permissions**.
- You should **pin GitHub Actions by full commit SHA** using your existing pinning script before enabling required checks.

## License

Apache-2.0

An experimental NGINX + OpenSSL 3 + OQS provider TLS terminator lives in `terminators/nginx-oqs/`.
It builds `liboqs` and `oqs-provider`, auto-loads the provider via `openssl.cnf`, and exposes a
TLS 1.3 endpoint advertising hybrid/PQC groups configured by `ssl_conf_command`.

Bring it up with Docker Compose:

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout certs/server.key -out certs/server.crt -subj "/CN=localhost"

docker compose build pqc_proxy
docker compose up
```

Then:
* App API (plaintext) → http://localhost:8080
* PQC TLS sidecar → https://localhost:443

List available hybrid/PQC groups inside the sidecar:

```bash
docker compose exec pqc_proxy openssl list -groups -provider oqsprovider
```

Update `ALLOWED_GROUPS` env and matching `ssl_conf_command Options -Groups` in `nginx.conf` to
experiment with different hybrid sets.

## Receipt Schema (Outward View)

Each stored receipt internally uses `kind`. API responses also project outward convenience fields:

- `type`: alias of `kind`
- `time`: RFC3339 derived from `ts_ms`
- `policy_id`: alias of `policy_version`
Health endpoints: `/health` and `/healthz`.

## Integration Test (Optional)

A two-phase integration test exercises an allow event then a restricted proxy phase. Enable with `RUN_INT=1`:

```powershell

## TLS Terminator Integration (MVP)

An NGINX-based TLS front end can inject the negotiated tuple into the control plane via headers
and/or structured access logs. Two configs are provided:

- `docker/nginx/nginx.default.conf` – standard hybrid-capable stack (placeholder hybrid mapping).
- `docker/nginx/nginx.restricted.conf` – restricted groups to force deny receipts.

The `handshake_tailer.py` script (under `terminators/nginx-oqs/`) can be run as a sidecar to tail
`/var/log/nginx/handshake.log` (log_format `handshake`) and POST `pqc.enforcement` allow receipts
representing the effective negotiated tuple observed on real connections. Policy denial continues
to be enforced server-side (soft mode) until a direct enforcement channel is wired.

Example docker snippet:

```
  tailer:
    image: python:3.12-slim
    volumes:
      - ./docker/nginx/logs:/var/log/nginx:ro
    working_dir: /app
    command: ["python","/mount/handshake_tailer.py"]
    volumes:
      - ./terminators/nginx-oqs/handshake_tailer.py:/mount/handshake_tailer.py:ro
    environment:
      CONTROL_PLANE_URL: http://app:8000
```

Future enhancements: extract actual signature/KEM algorithms from oqs-provider enabled OpenSSL,
and push policy decisions down into dynamic NGINX variables for pre-TLS enforcement.
make int-test
```

Phase A starts the default compose and posts an allow `pqc.enforcement` receipt. Phase B restarts the proxy with `docker/compose.restricted.yml`, triggering a different receipt (e.g. soft policy deny) which the test detects via `/receipts/latest`.
