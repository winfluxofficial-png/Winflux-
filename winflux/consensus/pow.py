"""Proof of Work: anyone can mine; nobody has special authority.

Rules
-----
* The block is valid if `int(block_hash, 16) <= target`. The hash is the header's (SHA-256 with
  domain separation), which already includes the nonce. Producer and signature stay empty: whoever receives the
  reward is just the coinbase address.
* The target does NOT go in the header: it is derived from history (as in Ethereum), so nobody can
  declare their own difficulty. Every `pow_retarget_interval` blocks the target is recomputed from the
  actual time spent in the last intervals, with the adjustment limited to 4x up or down.
* The winning chain is the one with the MOST ACCUMULATED WORK (not the longest).

Known limitation: SHA-256 favors dedicated hardware (ASIC). Choosing the algorithm is a
governance decision to be made before a network with real value (see docs/decentralization.md).
"""
import hashlib
import threading

from ..blockchain.block import Block
from ..blockchain.params import ChainParams
from ..crypto.hashing import canonical_json
from ..errors import ValidationError
from .interface import Consensus

MAX_ADJUST = 4
MAX_NONCE = 2**63 - 1
_SENTINEL = 999_999_999_999_999_999
_DOMAIN = b"WFLX-BLOCK-HEADER-V1"


def hash_to_int(block_hash_hex: str) -> int:
    return int(block_hash_hex, 16)


def work_for_target(target: int) -> int:
    """Expected work (average number of attempts) to find a hash <= target."""
    return (1 << 256) // (target + 1)


class ProofOfWork(Consensus):
    name = "pow"

    # ---- difficulty ----
    def next_target(self, prev: Block, params: ChainParams, view) -> int:
        limit = int(params.pow_limit, 16)
        interval = params.pow_retarget_interval
        height = prev.height + 1
        prev_target = view.target_of(prev.hash) if prev.height > 0 else limit
        if height % interval != 0:
            return prev_target
        first = view.ancestor(prev, interval - 1)           # block at height `height - interval`
        if first is None:
            return prev_target
        expected = (interval - 1) * params.target_block_time
        actual = max(1, prev.timestamp - first.timestamp)
        actual = min(max(actual, expected // MAX_ADJUST), expected * MAX_ADJUST)
        return max(1, min(limit, prev_target * actual // expected))

    def block_work(self, target: int) -> int:
        return work_for_target(target)

    # ---- verification ----
    def verify_block(self, block: Block, prev: Block, params: ChainParams, view=None) -> None:
        if prev is None or view is None:
            raise ValidationError("PoW requires the chain context (target derived from history)")
        if block.producer != "" or block.signature != "":
            raise ValidationError("a PoW block has no producer or signature")
        if block.nonce > MAX_NONCE:
            raise ValidationError("nonce out of range")
        target = self.next_target(prev, params, view)
        if hash_to_int(block.hash) > target:
            raise ValidationError("insufficient proof of work")

    def seal(self, block: Block, keypair=None) -> Block:
        raise ValidationError("in PoW use mine(); there is no key seal")

    # ---- mining ----
    @staticmethod
    def _split_header(block: Block):
        """Precomputes the canonical JSON prefix and suffix: only the nonce changes on each attempt."""
        h = block.header()
        h["nonce"] = _SENTINEL
        blob = _DOMAIN + canonical_json(h)
        marker = b'"nonce":%d' % _SENTINEL
        i = blob.index(marker)
        return blob[:i + len(b'"nonce":')], blob[i + len(marker):]

    @classmethod
    def search(cls, block: Block, target: int, start: int, count: int, stop: threading.Event | None = None):
        """Searches for a nonce in [start, start+count). Returns the nonce or None. Does not touch state."""
        prefix, suffix = cls._split_header(block)
        base = hashlib.sha256(prefix)
        end = min(start + count, MAX_NONCE + 1)
        for n in range(start, end):
            if stop is not None and (n & 0x3FFF) == 0 and stop.is_set():
                return None
            h = base.copy()
            h.update(b"%d" % n + suffix)
            if int.from_bytes(h.digest(), "big") <= target:
                return n
        return None

    @classmethod
    def mine(cls, block: Block, target: int, max_tries: int = 50_000_000,
             stop: threading.Event | None = None) -> Block | None:
        """Blocks until a nonce is found (or gives up). Returns the block with the nonce, or None."""
        n = cls.search(block, target, 0, max_tries, stop)
        if n is None:
            return None
        block.nonce = n
        return block
