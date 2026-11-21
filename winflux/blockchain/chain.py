"""Chain with a block tree, heaviest-work selection and reorganization (reorg).

* Every block with a known parent that passes the STATELESS rules (format, Merkle, consensus,
  time) enters the tree. Only the active chain is applied to the ledger.
* The active chain is the one with the most accumulated work. When a side branch overtakes the active one, the
  ledger undoes the blocks back to the common ancestor and applies the new branch, validating each transaction.
  If the new branch is invalid, the previous chain is restored and the branch is marked invalid.
* Blocks whose parent is unknown raise `OrphanBlock` (the node keeps them and asks for the parent).
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
    """The block's parent (prev_hash) is not known yet."""


class KnownBlock(ValidationError):
    """Block already known (duplicate)."""


@dataclass
class _Entry:
    block: Block
    work: int          # accumulated work up to this block (inclusive)
    target: int        # PoW target required for this block (0 in PoA)


@dataclass
class AddResult:
    status: str                                   # "extended" | "reorg" | "side"
    connected: list = field(default_factory=list)     # blocks that entered the active chain
    disconnected: list = field(default_factory=list)  # blocks that left it (reorg)


class Chain:
    def __init__(self, genesis: GenesisConfig, consensus: Consensus, storage=None, clock=time.time):
        self.params = genesis.params
        self.consensus = consensus
        self.storage = storage
        self._clock = clock
        self.genesis_block = build_genesis_block(genesis)
        self.blocks: list[Block] = []                 # active chain, index = height
        self.ledger = Ledger(self.params)
        self.utxo = self.ledger.utxo
        self.vaults = self.ledger.vaults
        self._undos: list[list] = []                  # undo records per active block
        self._index_by_hash: dict[str, _Entry] = {}   # all known blocks (tree)
        self._invalid: set[str] = set()
        self._tx_height: dict[str, int] = {}
        self._hash_height: dict[str, int] = {}
        self._seen_addresses: dict[str, int] = {}
        self._install_genesis()
        if storage is not None:
            self._load_from_storage()

    # ---------- initialization ----------
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
            raise StorageError("the stored genesis is not this network's")
        for b in stored[1:]:  # revalidates everything: the disk is not trusted
            try:
                self._accept_stateless(b, check_time=False)
                self._connect_active(b, check_time=False)
            except ValidationError as e:
                raise StorageError(f"stored block {b.height} is invalid: {e}") from None

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

    # ---------- view for consensus (difficulty) ----------
    def target_of(self, block_hash: str) -> int:
        return self._index_by_hash[block_hash].target

    def ancestor(self, block: Block, n: int) -> Block | None:
        """Block n steps before `block`, following `block`'s branch (not necessarily the active one)."""
        cur = block
        for _ in range(n):
            if cur.height == 0:
                return None
            ent = self._index_by_hash.get(cur.prev_hash)
            if ent is None:
                return None
            cur = ent.block
        return cur

    # ---------- queries ----------
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
        """Target required of the next block on top of the active tip (0 in PoA)."""
        return self.consensus.next_target(self.tip, self.params, self)

    def has_block(self, h: str) -> bool:
        return h in self._index_by_hash

    def is_invalid(self, h: str) -> bool:
        return h in self._invalid

    def get_block(self, height: int) -> Block | None:
        return self.blocks[height] if 0 <= height < len(self.blocks) else None

    def get_block_by_hash(self, h: str) -> Block | None:
        """ACTIVE-chain block with this hash (side branches are not returned)."""
        height = self._hash_height.get(h)
        return None if height is None else self.blocks[height]

    def get_any_block(self, h: str) -> Block | None:
        ent = self._index_by_hash.get(h)
        return None if ent is None else ent.block

    def get_transaction(self, txid: str):
        """(Transaction, height) or None."""
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
        """True if the address has ever received an output on the chain (used in wallet recovery)."""
        return address in self._seen_addresses

    def balance(self, address: str) -> int:
        return self.utxo.balance(address)

    def total_supply(self) -> int:
        return self.ledger.total_supply()

    def get_vault(self, vault_id: str):
        return self.vaults.get(vault_id)

    def check_transaction(self, tx: Transaction) -> int:
        """Validates a transaction against the current state (used by the mempool). Returns the fee."""
        return self.ledger.check(tx, self.height + 1).fee

    # ---------- synchronization ----------
    def locator(self) -> list:
        """Active-chain hashes from the tip backwards with growing steps (ends at the genesis)."""
        out, step, h = [], 1, self.height
        while h > 0:
            out.append(self.blocks[h].hash)
            if len(out) >= 10:
                step *= 2
            h -= step
        out.append(self.blocks[0].hash)
        return out

    def blocks_after(self, locator, limit: int = 500) -> list:
        """Active-chain blocks right after the first locator hash that is on it."""
        start = 0
        for h in locator[:64]:
            if isinstance(h, str) and h in self._hash_height:
                start = self._hash_height[h]
                break
        return self.blocks[start + 1:start + 1 + max(0, limit)]

    # ---------- block production ----------
    def max_reward(self, height: int) -> int:
        """Allowed reward: halving schedule limited by the remaining supply."""
        return max(0, min(self.params.reward_at(height),
                          self.params.max_supply - self.ledger.total_supply()))

    def create_block(self, producer_pubkey: str, reward_address: str, candidates,
                     timestamp: int | None = None) -> Block:
        """Builds a block (still without seal/nonce) with the valid transactions among `candidates`.

        In PoW use `producer_pubkey=""`.
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
            state_root = self.ledger.state_root()      # state AFTER the selected transactions
        finally:
            for u in reversed(undos):
                self.ledger.revert(u)
        outs = (TxOutput(reward, reward_address),) if reward > 0 else ()
        cb = Transaction(self.params.chain_id, (), outs, coinbase_height=height, payload=cb_payload)
        return Block.build(height, tip.hash, ts, producer_pubkey, [cb, *selected], state_root=state_root)

    # ---------- validation and connection ----------
    def add_block(self, block: Block) -> AddResult:
        """Validates and incorporates a block. Raises ValidationError (OrphanBlock/KnownBlock are subclasses)."""
        h = block.hash
        if h in self._invalid:
            raise ValidationError("block was already rejected as invalid")
        if h in self._index_by_hash:
            raise KnownBlock("block already known")
        parent = self._index_by_hash.get(block.prev_hash)
        if parent is None:
            raise OrphanBlock("unknown prev_hash (orphan block)")
        if block.prev_hash in self._invalid:
            raise ValidationError("the block descends from an invalid block")
        entry = self._accept_stateless(block, check_time=True)
        tip_ent = self._index_by_hash[self.tip.hash]
        if block.prev_hash == self.tip.hash:
            # common case: extends the tip. Validates the transactions; if it fails, the block is discarded.
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
        """Rules that do not depend on transaction state; records the block in the tree."""
        parent = self._index_by_hash[block.prev_hash].block
        p = self.params
        if block.height != parent.height + 1:
            raise ValidationError("unexpected height")
        if block.timestamp <= parent.timestamp:
            raise ValidationError("timestamp is not later than the previous block's")
        if check_time and block.timestamp > int(self._clock()) + p.max_future_drift:
            raise ValidationError("timestamp too far in the future")
        txs = block.transactions
        if not txs or len(txs) > p.max_block_txs:
            raise ValidationError("invalid number of transactions")
        if sum(t.size() for t in txs) > p.max_block_bytes:
            raise ValidationError("block exceeds the maximum size in bytes")
        ids = [t.txid for t in txs]
        if len(set(ids)) != len(ids):
            raise ValidationError("repeated txids in the block")
        if block.merkle_root != merkle_root(ids):
            raise ValidationError("Merkle root does not match")
        self.consensus.verify_block(block, parent, p, self)
        if not txs[0].is_coinbase or any(t.is_coinbase for t in txs[1:]):
            raise ValidationError("the block must have exactly one coinbase, in the first position")
        pe = self._index_by_hash[block.prev_hash]
        target = self.consensus.next_target(parent, p, self)
        ent = _Entry(block, pe.work + self.consensus.block_work(target), target)
        self._index_by_hash[block.hash] = ent
        return ent

    def _connect_active(self, block: Block, check_time: bool = False, persist: bool = False) -> None:
        """Applies the block (child of the active tip) to the ledger, validating each transaction."""
        prev, p = self.tip, self.params
        if block.prev_hash != prev.hash or block.height != prev.height + 1:
            raise ValidationError("prev_hash does not point to the chain tip")
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
                raise ValidationError("maximum supply exceeded")
            if block.state_root != self.ledger.state_root():
                raise ValidationError("block's state_root does not match the vault registry")
            if persist and self.storage is not None:
                self.storage.append_block(block)
        except Exception:
            for u in reversed(undos):  # atomicity: an invalid block leaves no trace
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
            for b in old:                       # restores the previous chain (it was valid)
                self._connect_active(b, check_time=False)
            bad = path[connected] if connected < len(path) else path[-1]
            self._mark_invalid(bad)
            raise
        return AddResult("reorg", list(path), disconnected)

    def _mark_invalid(self, block: Block) -> None:
        """Marks the block and all its known descendants as invalid."""
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
