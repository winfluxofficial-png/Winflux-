import json

import pytest

from winflux.crypto.address import is_valid_address, pubkey_to_address
from winflux.crypto.hashing import merkle_root, sha256_hex
from winflux.crypto.keys import (KeyPair, decrypt_keystore, encrypt_keystore,
                                verify_signature)
from winflux.errors import WalletError
from winflux.wallet.wallet import Wallet

from .conftest import KDF_N


def test_sha256_known_vector():
    assert sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_sign_and_verify():
    k = KeyPair.generate()
    sig = k.sign(b"msg")
    assert verify_signature(k.public_key, sig, b"msg")
    assert not verify_signature(k.public_key, sig, b"other")
    assert not verify_signature(KeyPair.generate().public_key, sig, b"msg")
    assert not verify_signature(k.public_key, sig[:-1] + bytes([sig[-1] ^ 1]), b"msg")
    assert not verify_signature(b"short", sig, b"msg")


def test_keypair_deterministic_and_repr_hides_seed():
    a, b = KeyPair(b"\x07" * 32), KeyPair(b"\x07" * 32)
    assert a.address == b.address
    assert a.seed.hex() not in repr(a)


def test_keypair_rejects_bad_seed():
    with pytest.raises(ValueError):
        KeyPair(b"short")


def test_address_roundtrip_and_checksum():
    k = KeyPair.generate()
    assert k.address.startswith("wflx1") and is_valid_address(k.address)
    assert pubkey_to_address(k.public_key) == k.address
    bad = k.address[:-1] + ("a" if k.address[-1] != "a" else "b")
    assert not is_valid_address(bad)
    assert not is_valid_address(k.address.upper())
    for junk in ("", "wflx1", "btc1abc", None, 123, "wflx1" + "a" * 100):
        assert not is_valid_address(junk)


def test_keystore_roundtrip_and_wrong_password():
    k = KeyPair.generate()
    ks = encrypt_keystore(k, "test-password-123", n=KDF_N)
    assert k.seed.hex() not in json.dumps(ks)  # never in plain text
    assert decrypt_keystore(ks, "test-password-123").address == k.address
    with pytest.raises(WalletError):
        decrypt_keystore(ks, "wrong-password-123")


def test_keystore_tamper_detected():
    k = KeyPair.generate()
    ks = encrypt_keystore(k, "test-password-123", n=KDF_N)
    ks["ciphertext"] = ("00" if ks["ciphertext"][:2] != "00" else "01") + ks["ciphertext"][2:]
    with pytest.raises(WalletError):
        decrypt_keystore(ks, "test-password-123")
    ks2 = encrypt_keystore(k, "test-password-123", n=KDF_N)
    ks2["address"] = KeyPair.generate().address
    with pytest.raises(WalletError):
        decrypt_keystore(ks2, "test-password-123")


def test_keystore_rejects_weak_password_and_abusive_kdf():
    k = KeyPair.generate()
    with pytest.raises(WalletError):
        encrypt_keystore(k, "short", n=KDF_N)
    ks = encrypt_keystore(k, "test-password-123", n=KDF_N)
    ks["kdf_params"]["n"] = 2**30  # memory DoS attempt
    with pytest.raises(WalletError):
        decrypt_keystore(ks, "test-password-123")
    with pytest.raises(WalletError):
        decrypt_keystore({"garbage": 1}, "test-password-123")


def test_wallet_file_save_load(tmp_path):
    w = Wallet.create()
    p = tmp_path / "w.json"
    w.save(str(p), "test-password-123", kdf_n=KDF_N)
    assert Wallet.load(str(p), "test-password-123").address == w.address
    assert (p.stat().st_mode & 0o777) == 0o600
    with pytest.raises(FileExistsError):
        w.save(str(p), "test-password-123", kdf_n=KDF_N)
    with pytest.raises(WalletError):
        Wallet.load(str(tmp_path / "does-not-exist.json"), "x")


def test_merkle_root_properties():
    a, b, c = (sha256_hex(x) for x in (b"a", b"b", b"c"))
    assert merkle_root([a]) == a
    assert merkle_root([a, b]) != merkle_root([b, a])
    assert merkle_root([a, b, c]) != merkle_root([a, b])
