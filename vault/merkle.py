"""Merkle tree for batch-sealing case evidence."""
import hashlib


def compute_merkle_root(hashes):
    """Return the Merkle root of a list of SHA-256 hex strings, or '' if empty."""
    hashes = [h for h in hashes if h]
    if not hashes:
        return ''

    level = list(hashes)
    if len(level) % 2:
        level.append(level[-1])   # duplicate odd leaf

    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            pair = level[i] + level[i + 1]
            next_level.append(hashlib.sha256(pair.encode()).hexdigest())
        level = next_level
        if len(level) > 1 and len(level) % 2:
            level.append(level[-1])

    return level[0]


def merkle_proof_path(hashes, target):
    """Return the list of sibling hashes needed to verify `target` against root."""
    hashes = [h for h in hashes if h]
    if target not in hashes:
        return []
    level = list(hashes)
    if len(level) % 2:
        level.append(level[-1])
    path = []
    while len(level) > 1:
        idx = level.index(target) if target in level else None
        if idx is None:
            return []
        sibling_idx = idx + 1 if idx % 2 == 0 else idx - 1
        if sibling_idx < len(level):
            path.append(level[sibling_idx])
        next_level = []
        for i in range(0, len(level), 2):
            pair = level[i] + level[i + 1]
            next_level.append(hashlib.sha256(pair.encode()).hexdigest())
        level = next_level
        if len(level) > 1 and len(level) % 2:
            level.append(level[-1])
        target = level[-1] if target not in level else target
    return path