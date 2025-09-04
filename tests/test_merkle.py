
import hashlib

from spcp.receipts.merkle import inclusion_proof, merkle_root, verify_inclusion


def _h(b): 
    return hashlib.sha256(b).digest()

def test_merkle_inclusion():
    leaves = [b"a", b"b", b"c", b"d", b"e"]
    leaf_hashes = [_h(x) for x in leaves]
    root = merkle_root(leaf_hashes)
    for i, h in enumerate(leaf_hashes):
        proof = inclusion_proof(i, leaf_hashes)
        assert verify_inclusion(h, root, proof)
