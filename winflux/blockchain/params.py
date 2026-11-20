"""Parâmetros monetários e de consenso da rede (imutáveis para uma dada chain)."""
from dataclasses import dataclass

from ..crypto.hashing import canonical_json, sha256_hex
from ..errors import ValidationError


@dataclass(frozen=True)
class ChainParams:
    chain_id: str
    name: str
    symbol: str
    decimals: int
    max_supply: int          # em unidades
    block_reward: int        # em unidades
    halving_interval: int    # blocos; 0 = sem halving
    min_fee: int             # em unidades
    authorities: tuple       # pubkeys hex dos produtores (PoA de testes)
    max_block_txs: int = 2000
    max_tx_size: int = 100_000
    max_tx_inputs: int = 256
    max_tx_outputs: int = 256
    max_future_drift: int = 7200
    min_fee_per_byte: int = 1       # taxa mínima proporcional ao tamanho (unidades/byte)
    max_block_bytes: int = 1_000_000  # tamanho máximo do bloco (JSON canônico)
    # --- cofres offline (docs/offline-payments.md, Revisão 2) ---
    target_block_time: int = 5          # segundos (devnet); converte tempo <-> altura
    vault_max_slots: int = 64
    vault_collateral_min_pct: int = 100  # ρ mínimo, em %
    vault_ttl_min_blocks: int = 17_280   # ~1 dia a 5 s/bloco
    vault_ttl_max_blocks: int = 518_400  # ~30 dias
    claim_window_blocks: int = 120_960   # ~7 dias após a expiração
    min_voucher: int = 0                 # 0 => 10 x min_fee
    vault_max_value: int = 10_000 * 10**8
    max_compensations_per_slot: int = 16  # R9 (exposure.py): limita estado e verificação
    # --- consenso público (PoW) e maturidade ---
    consensus: str = "poa"               # "poa" (testes, autoridades) | "pow" (sem autoridades)
    pow_limit: str = "f" * 64            # alvo máximo (dificuldade mínima), hex de 64 dígitos
    pow_retarget_interval: int = 144     # blocos entre ajustes de dificuldade
    coinbase_maturity: int = 0           # blocos até a recompensa poder ser gasta (0 = imediato)

    def __post_init__(self):
        def bad(msg):
            raise ValidationError(f"parâmetros inválidos: {msg}")
        if not self.chain_id or len(self.chain_id) > 64:
            bad("chain_id")
        if not (0 <= self.decimals <= 18):
            bad("decimals")
        if self.max_supply <= 0 or self.block_reward < 0 or self.min_fee < 0:
            bad("valores monetários")
        if self.halving_interval < 0:
            bad("halving_interval")
        if self.max_block_txs < 1:
            bad("max_block_txs")
        if self.min_fee_per_byte < 0:
            bad("min_fee_per_byte")
        if self.max_block_bytes < 4000:
            bad("max_block_bytes")
        if not 1 <= self.vault_max_slots <= 65_535:
            bad("vault_max_slots")
        if not 0 <= self.vault_collateral_min_pct <= 1000:
            bad("vault_collateral_min_pct")
        if not 1 <= self.vault_ttl_min_blocks <= self.vault_ttl_max_blocks:
            bad("vault_ttl")
        if self.claim_window_blocks < 1 or self.target_block_time < 1:
            bad("claim_window_blocks/target_block_time")
        if self.min_voucher < 0 or self.vault_max_value <= 0:
            bad("min_voucher/vault_max_value")
        if not 1 <= self.max_compensations_per_slot <= 256:
            bad("max_compensations_per_slot")
        if self.consensus not in ("poa", "pow"):
            bad("consensus")
        if not (isinstance(self.pow_limit, str) and len(self.pow_limit) == 64
                and all(c in "0123456789abcdef" for c in self.pow_limit)
                and int(self.pow_limit, 16) > 0):
            bad("pow_limit")
        if not 2 <= self.pow_retarget_interval <= 100_000:
            bad("pow_retarget_interval")
        if not 0 <= self.coinbase_maturity <= 10_000:
            bad("coinbase_maturity")
        if self.consensus == "pow" and self.authorities:
            bad("rede PoW não tem autoridades (ninguém tem poder privilegiado)")

    @property
    def min_voucher_value(self) -> int:
        return self.min_voucher or 10 * self.min_fee

    def reward_at(self, height: int) -> int:
        """Recompensa agendada (antes de aplicar o teto de oferta)."""
        if self.halving_interval == 0:
            return self.block_reward
        halvings = height // self.halving_interval
        return 0 if halvings >= 64 else self.block_reward >> halvings

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id, "name": self.name, "symbol": self.symbol,
            "decimals": self.decimals, "max_supply": self.max_supply,
            "block_reward": self.block_reward, "halving_interval": self.halving_interval,
            "min_fee": self.min_fee, "authorities": list(self.authorities),
            "max_block_txs": self.max_block_txs, "max_tx_size": self.max_tx_size,
            "max_tx_inputs": self.max_tx_inputs, "max_tx_outputs": self.max_tx_outputs,
            "max_future_drift": self.max_future_drift,
            "min_fee_per_byte": self.min_fee_per_byte, "max_block_bytes": self.max_block_bytes,
            "target_block_time": self.target_block_time, "vault_max_slots": self.vault_max_slots,
            "vault_collateral_min_pct": self.vault_collateral_min_pct,
            "vault_ttl_min_blocks": self.vault_ttl_min_blocks,
            "vault_ttl_max_blocks": self.vault_ttl_max_blocks,
            "claim_window_blocks": self.claim_window_blocks, "min_voucher": self.min_voucher,
            "vault_max_value": self.vault_max_value,
            "max_compensations_per_slot": self.max_compensations_per_slot,
            "consensus": self.consensus, "pow_limit": self.pow_limit,
            "pow_retarget_interval": self.pow_retarget_interval,
            "coinbase_maturity": self.coinbase_maturity,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ChainParams":
        try:
            d = dict(d)
            d["authorities"] = tuple(d["authorities"])
            return cls(**d)
        except ValidationError:
            raise
        except Exception as e:
            raise ValidationError(f"parâmetros malformados: {e}") from None

    def commitment(self) -> str:
        """Hash dos parâmetros; vai no cabeçalho do gênese."""
        return sha256_hex(b"WFLX-PARAMS-V1" + canonical_json(self.to_dict()))
