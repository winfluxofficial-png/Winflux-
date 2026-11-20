"""Cadeia com árvore de blocos, escolha por maior trabalho e reorganização (reorg).

* Todo bloco com pai conhecido que passa nas regras SEM estado (formato, Merkle, consenso,
  tempo) entra na árvore. Só a cadeia ativa é aplicada ao ledger.
* A cadeia ativa é a de maior trabalho acumulado. Quando um ramo lateral supera a ativa, o
  ledger desfaz os blocos até o ancestral comum e aplica o novo ramo, validando cada transação.
  Se o novo ramo for inválido, a cadeia anterior é restaurada e o ramo é marcado como inválido.
* Blocos cujo pai é desconhecido levantam `OrphanBlock` (o nó os guarda e pede o pai).
"""
import time
from dataclasses import dataclass, field

from ..consensus.interface import Consensus
from ..crypto.hashing import merkle_root
from ..errors import StorageError, ValidationError
from .block import Block
from .genesis import GenesisConfig, build_genesis_block
from .transaction import Transaction, TxOutput
from .ledger import Ledger
from .validation import validate_coinbase


class OrphanBlock(ValidationError):
    """O pai (prev_hash) do bloco ainda não é conhecido."""


class KnownBlock(ValidationError):
    """Bloco já conhecido (duplicado)."""


@dataclass
class _Entry:
    block: Block
    work: int          # trabalho acumulado até este bloco (inclusive)
    target: int        # alvo PoW exigido deste bloco (0 em PoA)


@dataclass
class AddResult:
    status: str                                   # "extended" | "reorg" | "side"
    connected: list = field(default_factory=list)     # blocos que entraram na cadeia ativa
    disconnected: list = field(default_factory=list)  # blocos que saíram dela (reorg)


class Chain:
    def __init__(self, genesis: GenesisConfig, consensus: Consensus, storage=None, clock=time.time):
        self.params = genesis.params
        self.consensus = consensus
        self.storage = storage
        self._clock = clock
        self.genesis_block = build_genesis_block(genesis)
        self.blocks: list[Block] = []                 # cadeia ativa, índice = altura
        self.ledger = Ledger(self.params)
        self.utxo = self.ledger.utxo
        self.vaults = self.ledger.vaults
        self._undos: list[list] = []                  # desfazimentos por bloco ativo
        self._index_by_hash: dict[str, _Entry] = {}   # todos os blocos conhecidos (árvore)
        self._invalid: set[str] = set()
        self._tx_height: dict[str, int] = {}
        self._hash_height: dict[str, int] = {}
        self._seen_addresses: dict[str, int] = {}
        self._install_genesis()
        if storage is not None:
            self._load_from_storage()

    # ---------- inicialização ----------
    def _install_genesis(self):
        g = self.genesis_block
        limit = int(self.params.pow_limit, 16) if self.params.consensus == "pow" else 0
        self._index_by_hash[g.hash] = _Entry(g, 0, limit)
        self._undos.append([self.ledger.apply(g.transactions[0], None)])
        self.blocks.append(g)
        self._index(g)

    def _load_from_storage(self):
        stored = self.storage.load_blocks()
        if not stored:
            self.storage.append_block(self.genesis_block)
            return
        if stored[0].hash != self.genesis_block.hash:
            raise StorageError("o gênese armazenado não é o desta rede")
        for b in stored[1:]:  # revalida tudo: o disco não é confiável
            try:
                self._accept_stateless(b, check_time=False)
                self._connect_active(b, check_time=False)
            except ValidationError as e:
                raise StorageError(f"bloco {b.height} armazenado é inválido: {e}") from None

    def _index(self, block: Block):
        self._hash_height[block.hash] = block.height
        for t in block.transactions:
            self._tx_height[t.txid] = block.height
            for o in t.outputs:
                self._seen_addresses[o.address] = self._seen_addresses.get(o.address, 0) + 1

    def _unindex(self, block: Block):
        self._hash_height.pop(block.hash, None)
        for t in block.transactions:
            self._tx_height.pop(t.txid, None)
            for o in t.outputs:
                n = self._seen_addresses.get(o.address, 0) - 1
                if n > 0:
                    self._seen_addresses[o.address] = n
                else:
                    self._seen_addresses.pop(o.address, None)

    # ---------- visão para o consenso (dificuldade) ----------
    def target_of(self, block_hash: str) -> int:
        return self._index_by_hash[block_hash].target

    def ancestor(self, block: Block, n: int) -> Block | None:
        """Bloco n passos antes de `block`, seguindo o ramo de `block` (não necessariamente o ativo)."""
        cur = block
        for _ in range(n):
            if cur.height == 0:
                return None
            ent = self._index_by_hash.get(cur.prev_hash)
            if ent is None:
                return None
            cur = ent.block
        return cur

    # ---------- consultas ----------
    @property
    def tip(self) -> Block:
        return self.blocks[-1]

    @property
    def height(self) -> int:
        return self.tip.height

    @property
    def total_work(self) -> int:
        return self._index_by_hash[self.tip.hash].work

    def next_target(self) -> int:
        """Alvo exigido do próximo bloco sobre o topo ativo (0 em PoA)."""
        return self.consensus.next_target(self.tip, self.params, self)

    def has_block(self, h: str) -> bool:
        return h in self._index_by_hash

    def is_invalid(self, h: str) -> bool:
        return h in self._invalid

    def get_block(self, height: int) -> Block | None:
        return self.blocks[height] if 0 <= height < len(self.blocks) else None

    def get_block_by_hash(self, h: str) -> Block | None:
        """Bloco da cadeia ATIVA com esse hash (ramos laterais não são devolvidos)."""
        height = self._hash_height.get(h)
        return None if height is None else self.blocks[height]

    def get_any_block(self, h: str) -> Block | None:
        ent = self._index_by_hash.get(h)
        return None if ent is None else ent.block

    def get_transaction(self, txid: str):
        """(Transaction, altura) ou None."""
        height = self._tx_height.get(txid)
        if height is None:
            return None
        for t in self.blocks[height].transactions:
            if t.txid == txid:
                return t, height
        return None

    def confirmations(self, txid: str) -> int:
        h = self._tx_height.get(txid)
        return 0 if h is None else self.height - h + 1

    def address_seen(self, address: str) -> bool:
        """True se o endereço já recebeu alguma saída na cadeia (usado na recuperação de carteiras)."""
        return address in self._seen_addresses

    def balance(self, address: str) -> int:
        return self.utxo.balance(address)

    def total_supply(self) -> int:
        return self.ledger.total_supply()

    def get_vault(self, vault_id: str):
        return self.vaults.get(vault_id)

    def check_transaction(self, tx: Transaction) -> int:
        """Valida uma transação contra o estado atual (usada pelo mempool). Retorna a taxa."""
        return self.ledger.check(tx, self.height + 1).fee

    # ---------- sincronização ----------
    def locator(self) -> list:
        """Hashes da cadeia ativa do topo para trás com passos crescentes (termina no gênese)."""
        out, step, h = [], 1, self.height
        while h > 0:
            out.append(self.blocks[h].hash)
            if len(out) >= 10:
                step *= 2
            h -= step
        out.append(self.blocks[0].hash)
        return out

    def blocks_after(self, locator, limit: int = 500) -> list:
        """Blocos da cadeia ativa logo após o primeiro hash do localizador que esteja nela."""
        start = 0
        for h in locator[:64]:
            if isinstance(h, str) and h in self._hash_height:
                start = self._hash_height[h]
                break
        return self.blocks[start + 1:start + 1 + max(0, limit)]

    # ---------- produção de blocos ----------
    def max_reward(self, height: int) -> int:
        """Recompensa permitida: agenda de halving limitada pela oferta restante."""
        return max(0, min(self.params.reward_at(height),
                          self.params.max_supply - self.ledger.total_supply()))

    def create_block(self, producer_pubkey: str, reward_address: str, candidates,
                     timestamp: int | None = None) -> Block:
        """Monta um bloco (ainda sem selo/nonce) com as transações válidas dentre `candidates`.

        Em PoW use `producer_pubkey=""`.
        """
        tip = self.tip
        height = tip.height + 1
        ts = timestamp if timestamp is not None else max(int(self._clock()), tip.timestamp + 1)
        selected, undos, fees, used = [], [], 0, 0
        cb_payload = {"prev_hash": tip.hash}
        cb_bound = Transaction(self.params.chain_id, (), (TxOutput(self.params.max_supply, reward_address),),
                               coinbase_height=height, payload=cb_payload).size()
        budget = self.params.max_block_bytes - cb_bound
        try:
            for tx in candidates:
                if len(selected) >= self.params.max_block_txs - 1:
                    break
                size = tx.size()
                if used + size > budget:
                    continue
                try:
                    checked = self.ledger.check(tx, height)
                    undos.append(self.ledger.apply(tx, checked))
                except ValidationError:
                    continue
                fee = checked.fee
                selected.append(tx)
                used += size
                fees += fee
            reward = self.max_reward(height) + fees
            state_root = self.ledger.state_root()      # estado APÓS as transações selecionadas
        finally:
            for u in reversed(undos):
                self.ledger.revert(u)
        outs = (TxOutput(reward, reward_address),) if reward > 0 else ()
        cb = Transaction(self.params.chain_id, (), outs, coinbase_height=height, payload=cb_payload)
        return Block.build(height, tip.hash, ts, producer_pubkey, [cb, *selected], state_root=state_root)

    # ---------- validação e conexão ----------
    def add_block(self, block: Block) -> AddResult:
        """Valida e incorpora um bloco. Levanta ValidationError (OrphanBlock/KnownBlock são subclasses)."""
        h = block.hash
        if h in self._invalid:
            raise ValidationError("bloco já foi rejeitado como inválido")
        if h in self._index_by_hash:
            raise KnownBlock("bloco já conhecido")
        parent = self._index_by_hash.get(block.prev_hash)
        if parent is None:
            raise OrphanBlock("prev_hash desconhecido (bloco órfão)")
        if block.prev_hash in self._invalid:
            raise ValidationError("o bloco descende de um bloco inválido")
        entry = self._accept_stateless(block, check_time=True)
        tip_ent = self._index_by_hash[self.tip.hash]
        if block.prev_hash == self.tip.hash:
            # caso comum: estende o topo. Valida as transações; se falhar, o bloco é descartado.
            try:
                self._connect_active(block, check_time=False, persist=True)
            except Exception:
                self._drop(block)
                raise
            return AddResult("extended", [block], [])
        if entry.work > tip_ent.work:
            return self._reorganize(block)
        return AddResult("side")

    def _drop(self, block: Block) -> None:
        self._index_by_hash.pop(block.hash, None)

    def _accept_stateless(self, block: Block, check_time: bool) -> _Entry:
        """Regras que não dependem do estado das transações; registra o bloco na árvore."""
        parent = self._index_by_hash[block.prev_hash].block
        p = self.params
        if block.height != parent.height + 1:
            raise ValidationError("altura inesperada")
        if block.timestamp <= parent.timestamp:
            raise ValidationError("timestamp não é posterior ao do bloco anterior")
        if check_time and block.timestamp > int(self._clock()) + p.max_future_drift:
            raise ValidationError("timestamp muito no futuro")
        txs = block.transactions
        if not txs or len(txs) > p.max_block_txs:
            raise ValidationError("número de transações inválido")
        if sum(t.size() for t in txs) > p.max_block_bytes:
            raise ValidationError("bloco excede o tamanho máximo em bytes")
        ids = [t.txid for t in txs]
        if len(set(ids)) != len(ids):
            raise ValidationError("txids repetidos no bloco")
        if block.merkle_root != merkle_root(ids):
            raise ValidationError("raiz de Merkle não confere")
        self.consensus.verify_block(block, parent, p, self)
        if not txs[0].is_coinbase or any(t.is_coinbase for t in txs[1:]):
            raise ValidationError("o bloco deve ter exatamente uma coinbase, na primeira posição")
        pe = self._index_by_hash[block.prev_hash]
        target = self.consensus.next_target(parent, p, self)
        ent = _Entry(block, pe.work + self.consensus.block_work(target), target)
        self._index_by_hash[block.hash] = ent
        return ent

    def _connect_active(self, block: Block, check_time: bool = False, persist: bool = False) -> None:
        """Aplica o bloco (filho do topo ativo) ao ledger, validando cada transação."""
        prev, p = self.tip, self.params
        if block.prev_hash != prev.hash or block.height != prev.height + 1:
            raise ValidationError("prev_hash não aponta para o topo da cadeia")
        txs = block.transactions
        supply_before = self.ledger.total_supply()
        undos, fees = [], 0
        try:
            for tx in txs[1:]:
                checked = self.ledger.check(tx, block.height)
                fees += checked.fee
                undos.append(self.ledger.apply(tx, checked))
            allowed = max(0, min(p.reward_at(block.height), p.max_supply - supply_before)) + fees
            validate_coinbase(txs[0], block.height, p, allowed, block.prev_hash)
            undos.append(self.ledger.apply(txs[0], None))
            if self.ledger.total_supply() > p.max_supply:
                raise ValidationError("oferta máxima excedida")
            if block.state_root != self.ledger.state_root():
                raise ValidationError("state_root do bloco não confere com o registro de cofres")
            if persist and self.storage is not None:
                self.storage.append_block(block)
        except Exception:
            for u in reversed(undos):  # atomicidade: bloco inválido não deixa rastro
                self.ledger.revert(u)
            raise
        self.blocks.append(block)
        self._undos.append(undos)
        self._index(block)

    def _disconnect_tip(self) -> Block:
        block = self.blocks.pop()
        for u in reversed(self._undos.pop()):
            self.ledger.revert(u)
        self._unindex(block)
        return block

    def _is_active(self, block: Block) -> bool:
        return block.height < len(self.blocks) and self.blocks[block.height].hash == block.hash

    def _reorganize(self, new_tip: Block) -> AddResult:
        path, cur = [], new_tip
        while not self._is_active(cur):
            path.append(cur)
            cur = self._index_by_hash[cur.prev_hash].block
        path.reverse()
        fork_height = cur.height
        old = self.blocks[fork_height + 1:]
        disconnected = []
        for _ in old:
            disconnected.append(self._disconnect_tip())
        connected = 0
        try:
            for b in path:
                self._connect_active(b, check_time=False)
                connected += 1
            if self.storage is not None:
                self.storage.reorganize(fork_height, path)
        except Exception:
            for _ in range(connected):
                self._disconnect_tip()
            for b in old:                       # restaura a cadeia anterior (era válida)
                self._connect_active(b, check_time=False)
            bad = path[connected] if connected < len(path) else path[-1]
            self._mark_invalid(bad)
            raise
        return AddResult("reorg", list(path), disconnected)

    def _mark_invalid(self, block: Block) -> None:
        """Marca o bloco e todos os seus descendentes conhecidos como inválidos."""
        bad = {block.hash}
        changed = True
        while changed:
            changed = False
            for h, ent in list(self._index_by_hash.items()):
                if h not in bad and ent.block.prev_hash in bad:
                    bad.add(h)
                    changed = True
        for h in bad:
            self._invalid.add(h)
            self._index_by_hash.pop(h, None)
