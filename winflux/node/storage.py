"""Local block persistence in SQLite (the UTXO set is rebuilt on load)."""
import json
import sqlite3
import threading

from ..blockchain.block import Block
from ..errors import StorageError, ValidationError


class BlockStorage:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        try:
            self._db = sqlite3.connect(path, check_same_thread=False)
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("CREATE TABLE IF NOT EXISTS blocks("
                             "height INTEGER PRIMARY KEY, hash TEXT NOT NULL UNIQUE, "
                             "data TEXT NOT NULL)")
            self._db.commit()
        except sqlite3.Error as e:
            raise StorageError(f"could not open {path}: {e}") from None

    def load_blocks(self) -> list:
        with self._lock:
            try:
                rows = self._db.execute(
                    "SELECT height, hash, data FROM blocks ORDER BY height").fetchall()
            except sqlite3.Error as e:
                raise StorageError(f"read failed: {e}") from None
        blocks = []
        for expected_h, (height, h, data) in enumerate(rows):
            try:
                b = Block.from_dict(json.loads(data))
            except (ValueError, ValidationError) as e:
                raise StorageError(f"block {height} corrupted: {e}") from None
            if height != expected_h or b.height != height or b.hash != h:
                raise StorageError(f"block {height} inconsistent in storage")
            blocks.append(b)
        return blocks

    def append_block(self, block: Block) -> None:
        with self._lock:
            try:
                with self._db:
                    self._db.execute("INSERT INTO blocks(height, hash, data) VALUES(?,?,?)",
                                     (block.height, block.hash, json.dumps(block.to_dict())))
            except sqlite3.Error as e:
                raise StorageError(f"write failed: {e}") from None

    def reorganize(self, fork_height: int, new_blocks) -> None:
        """Swaps, in a single transaction, everything above `fork_height` for the `new_blocks`."""
        with self._lock:
            try:
                with self._db:
                    self._db.execute("DELETE FROM blocks WHERE height > ?", (fork_height,))
                    for b in new_blocks:
                        self._db.execute("INSERT INTO blocks(height, hash, data) VALUES(?,?,?)",
                                         (b.height, b.hash, json.dumps(b.to_dict())))
            except sqlite3.Error as e:
                raise StorageError(f"reorganization failed: {e}") from None

    def close(self) -> None:
        with self._lock:
            self._db.close()
