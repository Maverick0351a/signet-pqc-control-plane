
from __future__ import annotations
import hashlib, base64, json, time
from typing import List, Tuple

def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()

def build_merkle_tree(leaf_hashes: List[bytes]) -> List[List[bytes]]:
    """Return levels from leaves up to root (levels[0] = leaves)."""
    if not leaf_hashes:
        return [[_h(b'')]]  # empty tree sentinel
    levels = [leaf_hashes[:]]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt = []
        for i in range(0, len(cur), 2):
            left = cur[i]
            right = cur[i+1] if i + 1 < len(cur) else cur[i]
            nxt.append(_h(left + right))
        levels.append(nxt)
    return levels

def merkle_root(leaf_hashes: List[bytes]) -> bytes:
    return build_merkle_tree(leaf_hashes)[-1][0]

def inclusion_proof(leaf_index: int, leaf_hashes: List[bytes]) -> List[Tuple[str, str]]:
    """Return list of (dir, b64hash) pairs where dir in {'L','R'} meaning sibling direction."""
    levels = build_merkle_tree(leaf_hashes)
    proof = []
    idx = leaf_index
    for level in levels[:-1]:
        if idx % 2 == 0:
            # right sibling (or itself if no sibling)
            sib_idx = idx + 1 if idx + 1 < len(level) else idx
            direction = 'R'
        else:
            sib_idx = idx - 1
            direction = 'L'
        proof.append((direction, _b64(level[sib_idx])))
        idx //= 2
    return proof

def verify_inclusion(leaf_hash: bytes, root_hash: bytes, proof: List[Tuple[str, bytes]]) -> bool:
    cur = leaf_hash
    for direction, sib in proof:
        if isinstance(sib, str):
            sib = base64.b64decode(sib)
        if direction == 'R':
            cur = _h(cur + sib)
        else:
            cur = _h(sib + cur)
    return cur == root_hash

def build_sth(leaves_b64: List[str]) -> dict:
    leaf_hashes = [base64.b64decode(x) for x in leaves_b64]
    root = merkle_root(leaf_hashes)
    return {
        "tree_size": len(leaves_b64),
        "root_sha256_b64": _b64(root),
        "timestamp": int(time.time() * 1000),
        "hash_alg": "sha-256",
        "scheme": "merkle-v1"
    }
