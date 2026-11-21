"""Decentralization principles verifiable in code (docs/decentralization.md)."""
import pathlib
import re

import pytest

from winflux.blockchain.transaction import KINDS
from winflux.errors import ValidationError
from winflux.tools.netgen import make_genesis

from .conftest import kp
from .test_pow_reorg import make_pow_chain, mine_on, pow_params


def test_public_network_has_no_privileged_party():
    cfg = make_genesis("principles")
    assert cfg.params.consensus == "pow" and cfg.params.authorities == ()
    assert cfg.allocations == ()                      # no premine
    with pytest.raises(ValidationError):
        pow_params(authorities=("ab" * 32,))          # PoW does not accept authorities


def test_only_mining_creates_coins_and_supply_cap_holds():
    chain = make_pow_chain()
    for n in range(5):
        chain.add_block(mine_on(chain, kp(2 + n % 3).address))
    assert chain.total_supply() == 5 * chain.params.block_reward <= chain.params.max_supply
    assert not any(k in KINDS for k in ("mint", "freeze", "reverse", "set_balance", "upgrade"))


def test_any_address_can_mine_without_permission():
    chain = make_pow_chain()
    stranger = kp(77).address                          # never seen before
    assert chain.add_block(mine_on(chain, stranger)).status == "extended"
    assert chain.balance(stranger) == chain.params.block_reward


def test_no_admin_backdoors_in_source():
    root = pathlib.Path(__file__).resolve().parent.parent / "winflux"
    banned = re.compile(r"blacklist|whitelist|freeze_|kill_?switch|backdoor|admin_key|master_key|owner_key",
                        re.IGNORECASE)
    hits = [f"{p.name}:{i}" for p in root.rglob("*.py")
            for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1) if banned.search(line)]
    assert hits == []
