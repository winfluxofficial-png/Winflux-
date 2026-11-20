"""Fase 0: carteira HD, troco em endereço novo, chave de recuperação, taxa automática."""
import pytest

from winflux.blockchain.validation import required_fee
from winflux.errors import InsufficientFunds, WalletError
from winflux.wallet.hd import HDWallet, decode_recovery_key, derive_seed, encode_recovery_key
from winflux.wallet.wallet import Wallet

from .conftest import KDF_N, WFLX, make_chain, mine

SEED = bytes(range(32))


def funded(keys, hd, indexes=(0,), amount=1000 * WFLX):
    return make_chain(keys, alloc=tuple((hd.address(i), amount) for i in indexes))


def test_derivation_is_deterministic_and_distinct():
    assert derive_seed(SEED, 0) == derive_seed(SEED, 0)
    assert len({derive_seed(SEED, i) for i in range(50)}) == 50
    assert derive_seed(SEED, 0) != derive_seed(bytes(32), 0)
    with pytest.raises(ValueError):
        derive_seed(SEED, -1)


def test_recovery_key_roundtrip_and_typo_detection():
    rk = encode_recovery_key(SEED)
    assert rk.startswith("wflxk1-") and decode_recovery_key(rk) == SEED
    assert decode_recovery_key(rk.upper().replace("-", " ")) == SEED  # tolera formatação
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    for pos in (-1, -2, 10, 25):  # qualquer caractere trocado deve ser detectado (inclusive o último)
        chars = list(rk)
        chars[pos] = next(c for c in alphabet if c != chars[pos] and c != "-")
        with pytest.raises(WalletError):
            decode_recovery_key("".join(chars))
    for bad in ("", "wflxk1-", "btc-abcd", rk[:20]):
        with pytest.raises(WalletError):
            decode_recovery_key(bad)


def test_restore_from_recovery_key_gives_same_addresses():
    a = HDWallet(SEED)
    b = HDWallet.from_recovery_key(a.recovery_key())
    assert [a.address(i) for i in range(5)] == [b.address(i) for i in range(5)]


def test_pay_sends_change_to_a_fresh_address(keys):
    hd = HDWallet(SEED)
    chain = funded(keys, hd)
    tx = hd.pay(chain, keys["bob"].address, 10 * WFLX)
    change = [o for o in tx.outputs if o.address != keys["bob"].address]
    assert len(change) == 1 and change[0].address == hd.address(1) != hd.address(0)
    mine(chain, keys, [tx])
    assert chain.balance(keys["bob"].address) == 10 * WFLX
    assert chain.balance(hd.address(0)) == 0                      # endereço antigo esvaziado
    fee = 1000 * WFLX - 10 * WFLX - change[0].value
    assert fee >= chain.params.min_fee and chain.balance(hd.address(1)) == change[0].value
    assert hd.balance(chain) == chain.balance(hd.address(1))


def test_change_skips_addresses_already_on_chain(keys):
    """Endereço 0 recebeu fundos sem passar por new_address(): o troco NÃO pode voltar a ele."""
    hd = HDWallet(SEED)
    chain = funded(keys, hd)
    assert hd.next_index == 0 and chain.address_seen(hd.address(0))
    tx = hd.pay(chain, keys["bob"].address, WFLX)
    assert hd.address(0) not in [o.address for o in tx.outputs]
    assert hd.next_index == 2


def test_no_address_reuse_across_many_payments(keys):
    hd = HDWallet(SEED)
    chain = funded(keys, hd)
    change_addrs, spent_from = [], set()
    for _ in range(6):
        tx = hd.pay(chain, keys["bob"].address, WFLX)
        spent_from.update(pubkey for pubkey in (i.pubkey for i in tx.inputs))
        change_addrs += [o.address for o in tx.outputs if o.address != keys["bob"].address]
        mine(chain, keys, [tx])
    assert len(set(change_addrs)) == 6                    # um endereço novo a cada troco
    assert len(spent_from) == 6                           # cada chave pública exposta só uma vez
    assert hd.address(0) not in change_addrs


def test_pay_spends_from_several_addresses(keys):
    hd = HDWallet(SEED, next_index=3)
    chain = funded(keys, hd, indexes=(0, 1, 2), amount=100 * WFLX)
    tx = hd.pay(chain, keys["bob"].address, 250 * WFLX)    # exige as 3 origens
    assert len(tx.inputs) == 3 and len({i.pubkey for i in tx.inputs}) == 3
    mine(chain, keys, [tx])
    assert chain.balance(keys["bob"].address) == 250 * WFLX


def test_insufficient_funds(keys):
    hd = HDWallet(SEED)
    chain = funded(keys, hd, amount=5 * WFLX)
    with pytest.raises(InsufficientFunds):
        hd.pay(chain, keys["bob"].address, 10 * WFLX)
    assert hd.next_index == 0                              # falha não consome endereço


def test_auto_fee_is_minimal_and_accepted(keys):
    hd = HDWallet(SEED)
    chain = funded(keys, hd, indexes=tuple(range(40)), amount=100 * WFLX)
    hd.next_index = 40
    tx = hd.pay(chain, keys["bob"].address, 3500 * WFLX)    # muitas entradas => taxa por byte
    fee = chain.check_transaction(tx)
    assert fee == required_fee(tx, chain.params) > chain.params.min_fee
    mine(chain, keys, [tx])


def test_discover_restores_state_from_chain(keys):
    hd = HDWallet(SEED)
    chain = funded(keys, hd)
    for _ in range(3):
        mine(chain, keys, [hd.pay(chain, keys["bob"].address, WFLX)])
    restored = HDWallet.from_recovery_key(hd.recovery_key())
    assert restored.next_index == 0
    restored.discover(chain)
    assert restored.next_index == hd.next_index == 4   # índices 0..3 já usados
    assert restored.balance(chain) == hd.balance(chain) > 0
    mine(chain, keys, [restored.pay(chain, keys["carol"].address, WFLX)])  # consegue gastar


def test_from_existing_wallet_keystore(tmp_path):
    w = Wallet.create()
    p = tmp_path / "w.json"
    w.save(str(p), "senha-de-teste-123", kdf_n=KDF_N)
    a = HDWallet.from_wallet(Wallet.load(str(p), "senha-de-teste-123"))
    b = HDWallet.from_wallet(w)
    assert a.address(0) == b.address(0) and a.address(0) != w.address
