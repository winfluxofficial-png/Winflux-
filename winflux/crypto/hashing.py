"""SHA-256, serialização canônica e raiz de Merkle."""
import hashlib
import json


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj) -> bytes:
    """JSON determinístico: chaves ordenadas, sem espaços, ASCII."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def merkle_root(hashes: list[str]) -> str:
    """Raiz de Merkle de uma lista de hashes hex.

    Com número ímpar o último é duplicado; por isso o validador de blocos
    rejeita txids repetidos (evita a ambiguidade CVE-2012-2459).
    """
    if not hashes:
        return sha256_hex(b"")
    level = [bytes.fromhex(h) for h in hashes]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0].hex()
