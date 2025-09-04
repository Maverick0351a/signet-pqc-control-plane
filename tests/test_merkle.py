
import base64, hashlib, json, time
from spcp.receipts.merkle import build_merkle_tree, merkle_root, inclusion_proof, verify_inclusion

def _h(b): 
    import hashlib
    return hashlib.sha256(b).digest()

def test_merkle_inclusion():
    leaves = [b"a", b"b", b"c", b"d", b"e"]
    leaf_hashes = [_h(x) for x in leaves]
    root = merkle_root(leaf_hashes)
    for i, h in enumerate(leaf_hashes):
        proof = inclusion_proof(i, leaf_hashes)
        assert verify_inclusion(h, root, proof)
