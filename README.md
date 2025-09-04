
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

### One-liner (Docker Compose demo)

```bash
docker compose up --build -d && sleep 2 && \
  curl -s http://localhost:8000/echo -H 'X-TLS-Group: X25519' -H 'X-TLS-Protocol: TLS1.3' -H 'X-TLS-Cipher: TLS_AES_128_GCM_SHA256' >/dev/null && \
  echo 'ALLOW RECEIPT:' && curl -s http://localhost:8000/receipts/latest | jq '.policy.decision,.tls?//.negotiated_summary' && \
  # Now deny by removing X25519 from tuple policy
  curl -s -X PUT http://localhost:8000/tuple-policy -H 'Content-Type: application/json' \
    -d '{"policy_id":"deny-x25519","allowed":{"tls_version":["1.3"],"kx_groups":["secp256r1"],"sig_algs":[]},"deny_on_mismatch":true}' >/dev/null && \
  curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8000/echo -H 'X-TLS-Group: X25519' -H 'X-TLS-Protocol: TLS1.3' -H 'X-TLS-Cipher: TLS_AES_128_GCM_SHA256' && \
  echo 'DENY RECEIPT:' && curl -s http://localhost:8000/receipts/latest | jq '.policy.decision,.policy.reason'
```

### Manual (local venv)

```bash
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e '.[dev]'
pytest
uvicorn spcp.api.main:app --reload
```

Then:

```bash
# Allow path (default tuple policy includes X25519)
curl -s http://localhost:8000/echo -H 'X-TLS-Group: X25519' -H 'X-TLS-Protocol: TLS1.3' -H 'X-TLS-Cipher: TLS_AES_128_GCM_SHA256'
curl -s http://localhost:8000/receipts/latest | jq '.policy.decision,.tls?//.negotiated_summary'

# Deny path (restrict tuple policy)
curl -X PUT http://localhost:8000/tuple-policy -H 'Content-Type: application/json' \
  -d '{"policy_id":"deny-x25519","allowed":{"tls_version":["1.3"],"kx_groups":["secp256r1"],"sig_algs":[]},"deny_on_mismatch":true}'
curl -s -o /dev/null -w 'HTTP %{http_code}\n' http://localhost:8000/echo -H 'X-TLS-Group: X25519' -H 'X-TLS-Protocol: TLS1.3' -H 'X-TLS-Cipher: TLS_AES_128_GCM_SHA256'
curl -s http://localhost:8000/receipts/latest | jq '.policy.decision,.policy.reason'

# Collect CBOM
curl -X POST http://localhost:8000/cbom/collect
curl -s http://localhost:8000/cbom/latest | jq '.openssl.version,.proxy.policy_id'
```

### Compliance Pack

```bash
curl -X POST http://localhost:8000/compliance/pack -o compliance_pack.zip
unzip -l compliance_pack.zip
```

Contents: `sth.json`, raw `receipts/*.json`, optional `proofs/*.json`. (Future: helper verifier script.)

### PCH-Lite (Post-Connection Handshake Authorization) Overview

The control plane can require an additional per-request authorization step on selected routes.
This is a **"PCH-Lite"** profile: small, deterministic headers the client signs with an Ed25519
ephemeral (or provisioned) key to prove freshness, bind to the negotiated TLS channel, and
reference recent transparency evidence (STH / CBOM hash bundle).

Set `PCH_REQUIRED_ROUTES` (env var) to a list of glob patterns (e.g. `/protected*`) to enforce.

Headers (request / response):

| Header | Direction | Purpose |
|--------|-----------|---------|
| `WWW-Authenticate: PCH ...` | 401 response | Server challenge (base64 nonce inside `challenge="<:b64:>"`) |
| `PCH-Challenge` | 401 response + signed request | Echoes the challenge value (`:<b64>:` form). Signed as `pch-challenge` component. |
| `PCH-Channel-Binding` | signed request | Declares the channel binding kind & value. MVP: `tls-session-id=:<b64(session id)>:` |
| `PCH-Evidence` | signed request | Base64-wrapped JSON evidence reference – typically a simplified STH record: `{"type":"pch.sth","policy_id":...,"merkle_root_b64":...,"tree_size":...,"attestation":{...}}` |
| `Authorization` | signed request | `PCH keyId="<b64(ed25519 vk)>",alg="ed25519",created="<epoch>",challenge="<b64 nonce>",evidence="<b64 minimal JSON>",signature="<b64 sig>"` |
| `Signature-Input` | signed request | HTTP Message Signatures style list of covered pseudo-fields; MUST include `@method @path @authority pch-challenge pch-channel-binding pch-evidence` (+ `content-digest` if body) |
| `Content-Digest` | optional | Standard digest header if a body is present; then also covered. |

Canonical string to sign (lines joined with `\n`):
```
@method:GET
@path:/protected
@authority:example.com
pch-challenge::BASE64_NONCE:
pch-channel-binding:tls-session-id::BASE64_SESSION_ID:
pch-evidence::BASE64_EVIDENCE_JSON:
```
Signature = Ed25519(signing_key, UTF8(bytes_above)).

The server returns an enforcement receipt with a `pch` block:
```
"pch": {
  "present": true,
  "verified": true,
  "channel_binding": "tls-session-id",
  "challenge": ":BASE64_NONCE:",
  "evidence_ref": { "type":"pch.sth", "merkle_root_b64": "..." }
}
```

> Privacy: Evidence JSON is reduced to a small reference (Merkle root, CBOM hash, policy id). Host, path, or other PII-style keys are rejected if they appear inside evidence.

#### Curl / Shell Demonstration (Ephemeral Key via Python)

Below is an end-to-end demo using the `docker compose` stack (nginx PQC proxy on 8443, app on 8080)
and the `/protected` route enforced by `PCH_REQUIRED_ROUTES=/protected*`.

1. Get challenge (unauthenticated request → 401)
```bash
curl -sk -D /tmp/resp.hdrs https://localhost:8443/protected -o /dev/null
CHAL=$(grep -i '^PCH-Challenge:' /tmp/resp.hdrs | awk '{print $2}' | tr -d '\r')
echo "Challenge: $CHAL"
```
2. Build evidence JSON & sign request (Python inline for key + signature)
```bash
EVID_JSON='{"type":"pch.sth","time":'$(date +%s)',"policy_id":"vComposePCH","merkle_root_b64":"'$(python - <<PY | tr -d '\n'
import base64;print(base64.b64encode(b'0'*32).decode())
PY
)'","tree_size":1,"attestation":{"mode":"software","cbom_hash_b64":"'$(python - <<PY | tr -d '\n'
import base64;print(base64.b64encode(b'1'*32).decode())
PY
)'"}}'
EVID_B64=$(echo -n "$EVID_JSON" | python - <<PY
import base64,sys,json
raw=sys.stdin.buffer.read();print(base64.b64encode(raw).decode())
PY)
SESSION_ID="sess$(openssl rand -hex 4)" # simulate TLS session id (proxy usually injects X-TLS-Session-ID)
python - <<'PY'
import base64, os, sys, time, json
from nacl import signing
chal=os.environ['CHAL']
evid=os.environ['EVID_B64']
sid=os.environ['SESSION_ID']
vk_sk=signing.SigningKey.generate(); vk=vk_sk.verify_key
authority='localhost'
binding=f'tls-session-id=:{base64.b64encode(sid.encode()).decode()}:'
lines=[
  '@method:GET',
  '@path:/protected',
  f'@authority:{authority}',
  f'pch-challenge:{chal}',
  f'pch-channel-binding:{binding}',
  f'pch-evidence::{evid}:'.replace('::',':') if not evid.startswith(':') else f'pch-evidence:{evid}'
]
to_sign='\n'.join(lines).encode()
sig=vk_sk.sign(to_sign).signature
created=str(int(time.time()))
auth=(
  'PCH ' +
  f'keyId="{base64.b64encode(vk.encode()).decode()}",'
  f'alg="ed25519",created="{created}",' \
  f'challenge="{chal.strip(':')}",' \
  f'evidence="{base64.b64encode(json.dumps({"stub":True}).encode()).decode()}",' \
  f'signature="{base64.b64encode(sig).decode()}"'
)
sig_input='sig1=("@method" "@path" "@authority" "pch-challenge" "pch-channel-binding" "pch-evidence");created='+created
print('AUTH='+auth)
print('SIGINPUT='+sig_input)
print('BIND='+binding)
print('EVID_HDR=:'+evid+':')
PY
```
3. Issue signed request (variables exported by Python snippet)
```bash
curl -sk https://localhost:8443/protected \
  -H "Authorization: $AUTH" \
  -H "Signature-Input: $SIGINPUT" \
  -H "PCH-Challenge: $CHAL" \
  -H "PCH-Channel-Binding: $BIND" \
  -H "PCH-Evidence: $EVID_HDR" \
  -H "X-TLS-Session-ID: $SESSION_ID" \
  -H "X-TLS-Group: X25519" | jq
```
4. Fetch latest enforcement receipt (PCH verified)
```bash
curl -s http://localhost:8080/receipts/latest?type=pqc.enforcement | jq '.policy.decision,.pch.verified'
```

Common failure reasons (mapped to `pch.failure_reason` in deny receipts): `stale_challenge`, `binding_mismatch`, `missing_evidence`, `bad_signature`, `policy_id_mismatch`.

#### /receipts/latest API (PCH Aware)
```
GET /receipts/latest?type=pqc.enforcement&require_pch=true        # only receipts with pch.present
GET /receipts/latest?type=pqc.enforcement&raw=true                # internal stored shape
```

Use `raw=true` if you need the exact stored JSON (e.g. to recompute Merkle leaf hashes).

#### Compliance Pack With PCH
`POST /compliance/pack` (or GET) now includes `tools/verify_pch.py` which reconstructs the
covered components and verifies the Ed25519 signature inside the receipt's `pch` block.

```bash
curl -X POST http://localhost:8000/compliance/pack -o pack.zip
unzip -p pack.zip tools/verify_pch.py | head -n 20
python tools/verify_pch.py receipts/enforcement/enforcement_0.json
```

### TLS Session ID Caveat & Future Channel Bindings

TLS 1.3 **may not expose a stable session id** (some stacks disable session tickets / reuse or
zero out the identifier). If `X-TLS-Session-ID` is absent the current PCH-Lite binding will fail.

Roadmap / recommended path:
1. Adopt an Envoy (or similar) exporter that surfaces either a PRF-derived exporter (`tls-exporter`) or a resumable session identifier (when enabled) in a header the control plane can bind to.
2. Add support for `tls-exporter=:` binding variant (RFC 9261 style exporter) — code paths already structured to allow multiple kinds.
3. Retain session-id binding for stacks that still provide it, but prefer exporter-based binding for entropy and ubiquity.

Until then: ensure your proxy/terminator is configured to permit session tickets (or reuse) so a session id is generated, or patch your deployment to supply an alternate high-entropy binding header.

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
