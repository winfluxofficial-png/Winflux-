"""SHA-256, canonical serialization and Merkle root."""
import hashlib
import json


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj) -> bytes:
    """Deterministic JSON: sorted keys, no spaces, ASCII."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def merkle_root(hashes: list[str]) -> str:
    """Merkle root of a list of hex hashes.

    With an odd count the last one is duplicated; that is why the block validator
    rejects repeated txids (avoids the CVE-2012-2459 ambiguity).
    """
    if not hashes:
        return sha256_hex(b"")
    level = [bytes.fromhex(h) for h in hashes]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0].hex()
