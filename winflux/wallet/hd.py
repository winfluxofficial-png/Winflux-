"""Deterministic hierarchical (HD) wallet with a recovery key.

Each address comes from a master seed through HKDF-SHA256 ("hardened" derivation:
knowing a child address/key reveals neither the master nor the siblings). Change always
goes to a new address: this way each address tends to be spent only once,
which improves privacy and limits public-key exposure (relevant against
quantum attacks, see docs).
"""
import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..crypto.hashing import sha256
from ..crypto.keys import KeyPair
from ..errors import WalletError
from .transaction_builder import build_payment
from .wallet import Wallet

GAP_LIMIT = 20
RECOVERY_PREFIX = "wflxk1-"


def derive_seed(master: bytes, index: int) -> bytes:
    if not 0 <= index < 2**31:
        raise ValueError("index out of range")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"WFLX-HD-SALT-V1",
                info=b"WFLX-HD-V1/" + index.to_bytes(4, "big")).derive(master)


def encode_recovery_key(seed: bytes) -> str:
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    raw = seed + sha256(b"WFLX-RECOVERY-V1" + seed)[:4]
    b32 = base64.b32encode(raw).decode("ascii").lower().rstrip("=")
    return RECOVERY_PREFIX + "-".join(b32[i:i + 4] for i in range(0, len(b32), 4))


def decode_recovery_key(text: str) -> bytes:
    t = "".join(text.lower().replace("-", " ").split())  # tolerates hyphens, spaces and uppercase
    prefix = RECOVERY_PREFIX.rstrip("-")
    if not t.startswith(prefix):
        raise WalletError("recovery key with invalid prefix")
    body = t[len(prefix):]
    try:
        raw = base64.b32decode(body.upper() + "=" * (-len(body) % 8))
    except Exception:
        raise WalletError("malformed recovery key") from None
    canonical = base64.b32encode(raw).decode("ascii").lower().rstrip("=")
    if len(raw) != 36 or body != canonical or raw[32:] != sha256(b"WFLX-RECOVERY-V1" + raw[:32])[:4]:
        raise WalletError("invalid recovery key (typo?)")
    return raw[:32]


class HDWallet:
    def __init__(self, master_seed: bytes, next_index: int = 0):
        if not isinstance(master_seed, (bytes, bytearray)) or len(master_seed) != 32:
            raise ValueError("master seed must be 32 bytes")
        self._master = bytes(master_seed)
        self.next_index = next_index
        self._cache: dict[int, KeyPair] = {}

    @classmethod
    def generate(cls) -> "HDWallet":
        return cls(os.urandom(32))

    @classmethod
    def from_recovery_key(cls, text: str) -> "HDWallet":
        return cls(decode_recovery_key(text))

    @classmethod
    def from_wallet(cls, wallet: Wallet) -> "HDWallet":
        """Uses the existing keystore's seed as the master (the legacy address is not used)."""
        return cls(wallet.keypair.seed)

    def recovery_key(self) -> str:
        return encode_recovery_key(self._master)

    def keypair(self, index: int) -> KeyPair:
        if index not in self._cache:
            self._cache[index] = KeyPair(derive_seed(self._master, index))
        return self._cache[index]

    def address(self, index: int) -> str:
        return self.keypair(index).address

    def new_address(self) -> str:
        """Next receiving address (never reuses)."""
        a = self.address(self.next_index)
        self.next_index += 1
        return a

    def discover(self, chain, gap: int = GAP_LIMIT) -> None:
        """Recovers `next_index` from the chain (useful after restoring from the recovery key)."""
        i, last_used, misses = 0, -1, 0
        while misses < gap:
            if chain.address_seen(self.address(i)):
                last_used, misses = i, 0
            else:
                misses += 1
            i += 1
        self.next_index = max(self.next_index, last_used + 1)

    def _scan_limit(self) -> int:
        return self.next_index + GAP_LIMIT

    def utxos(self, chain) -> list:
        out = []
        for i in range(self._scan_limit()):
            out.extend(chain.utxo.utxos_for(self.address(i)))
        return out

    def balance(self, chain) -> int:
        return sum(chain.balance(self.address(i)) for i in range(self._scan_limit()))

    def pay(self, chain, to_address: str, amount: int, fee: int | None = None):
        """Builds and signs a payment; the change goes to a new address.

        Limitation: it does not track pending payments (mempool); two calls before
        the first one is included in a block may pick the same coins.
        """
        signers = {self.address(i): self.keypair(i) for i in range(self._scan_limit())}
        # Never reuses: skips addresses that already appear on the chain (e.g. a wallet restored
        # without `discover`, or a receiving address handed out without going through `new_address`).
        idx = self.next_index
        while chain.address_seen(self.address(idx)):
            idx += 1
        change = self.address(idx)
        tx = build_payment(signers, self.utxos(chain), to_address, amount, change,
                           chain.params.chain_id, fee, chain.params)
        if any(o.address == change for o in tx.outputs):
            self.next_index = idx + 1
        return tx
