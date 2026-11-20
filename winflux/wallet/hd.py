"""Carteira hierárquica determinística (HD) com chave de recuperação.

Cada endereço vem de uma semente-mestra por HKDF-SHA256 (derivação "endurecida":
conhecer um endereço/chave filha não revela a mestra nem as irmãs). O troco vai
sempre para um endereço novo: assim cada endereço costuma ser gasto uma única vez,
o que melhora a privacidade e limita a exposição da chave pública (relevante contra
ataques quânticos, ver docs).
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
        raise ValueError("índice fora do intervalo")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"WFLX-HD-SALT-V1",
                info=b"WFLX-HD-V1/" + index.to_bytes(4, "big")).derive(master)


def encode_recovery_key(seed: bytes) -> str:
    if len(seed) != 32:
        raise ValueError("semente deve ter 32 bytes")
    raw = seed + sha256(b"WFLX-RECOVERY-V1" + seed)[:4]
    b32 = base64.b32encode(raw).decode("ascii").lower().rstrip("=")
    return RECOVERY_PREFIX + "-".join(b32[i:i + 4] for i in range(0, len(b32), 4))


def decode_recovery_key(text: str) -> bytes:
    t = "".join(text.lower().replace("-", " ").split())  # tolera hífens, espaços e maiúsculas
    prefix = RECOVERY_PREFIX.rstrip("-")
    if not t.startswith(prefix):
        raise WalletError("chave de recuperação com prefixo inválido")
    body = t[len(prefix):]
    try:
        raw = base64.b32decode(body.upper() + "=" * (-len(body) % 8))
    except Exception:
        raise WalletError("chave de recuperação malformada") from None
    canonical = base64.b32encode(raw).decode("ascii").lower().rstrip("=")
    if len(raw) != 36 or body != canonical or raw[32:] != sha256(b"WFLX-RECOVERY-V1" + raw[:32])[:4]:
        raise WalletError("chave de recuperação inválida (erro de digitação?)")
    return raw[:32]


class HDWallet:
    def __init__(self, master_seed: bytes, next_index: int = 0):
        if not isinstance(master_seed, (bytes, bytearray)) or len(master_seed) != 32:
            raise ValueError("semente-mestra deve ter 32 bytes")
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
        """Usa a semente do keystore existente como mestra (o endereço legado não é usado)."""
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
        """Próximo endereço de recebimento (nunca reutiliza)."""
        a = self.address(self.next_index)
        self.next_index += 1
        return a

    def discover(self, chain, gap: int = GAP_LIMIT) -> None:
        """Recupera `next_index` a partir da cadeia (útil após restaurar pela chave de recuperação)."""
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
        """Monta e assina um pagamento; o troco vai para um endereço novo.

        Limitação: não rastreia pagamentos pendentes (mempool); duas chamadas antes de
        incluir o primeiro em bloco podem escolher as mesmas moedas.
        """
        signers = {self.address(i): self.keypair(i) for i in range(self._scan_limit())}
        # Nunca reutiliza: pula endereços que já aparecem na cadeia (ex.: carteira restaurada
        # sem `discover`, ou endereço de recebimento entregue sem passar por `new_address`).
        idx = self.next_index
        while chain.address_seen(self.address(idx)):
            idx += 1
        change = self.address(idx)
        tx = build_payment(signers, self.utxos(chain), to_address, amount, change,
                           chain.params.chain_id, fee, chain.params)
        if any(o.address == change for o in tx.outputs):
            self.next_index = idx + 1
        return tx
