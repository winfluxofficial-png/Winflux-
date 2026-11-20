"""A2: simulador de hardware e verificação de atestação."""
import copy
import random

import pytest

from winflux.errors import ValidationError
from winflux.offline.attestation import device_statement_bytes, key_statement_bytes, verify_attestation
from winflux.offline.hardware_sim import HardwareError, SimulatedRoot

NOW = 1_000_000


def make(level="strongbox", **kw):
    root = SimulatedRoot(seed=b"\x42" * 32)
    return root, root.provision(level, not_before=NOW - 100, not_after=NOW + 10**6, **kw)


def check(att, root, **kw):
    kw.setdefault("now", NOW)
    return verify_attestation(att, roots=[root.public_key], **kw)


@pytest.mark.parametrize("kt", ["p256", "ed25519"])
def test_valid_attestation_reports_properties(kt):
    root, hw = make()
    h = hw.generate_key(kt, b"\x07" * 16)
    r = check(h.attestation, root, expect_pubkey=h.public_hex, expect_key_type=kt, expect_challenge=(b"\x07" * 16).hex())
    assert r.level == "strongbox" and r.single_use and r.is_hardware and r.key_type == kt and r.pubkey == h.public_hex


def test_software_level_is_never_hardware():
    root, hw = make("software")
    r = check(hw.generate_key("p256", b"\x01" * 16).attestation, root)
    assert r.level == "software" and not r.single_use and not r.is_hardware


def test_single_use_not_requested_is_not_hardware():
    root, hw = make("tee")
    r = check(hw.generate_key("p256", b"\x01" * 16, single_use=False).attestation, root)
    assert r.level == "tee" and not r.single_use and not r.is_hardware


# ------------------------------------------------------------------ propriedades do hardware
def test_single_use_key_is_deleted_after_one_signature():
    _, hw = make()
    a, b = hw.generate_key("p256", b"\x01" * 16), hw.generate_key("ed25519", b"\x02" * 16)
    assert hw.has_key(a.handle) and a.sign(b"m1")
    assert not hw.has_key(a.handle)
    with pytest.raises(HardwareError, match="já usada"):
        a.sign(b"m2")                                        # segunda assinatura com a mesma chave
    assert b.sign(b"x") and hw.has_key(b.handle) is False     # outras chaves seguem independentes


def test_multi_use_key_allowed_when_not_single_use():
    _, hw = make("tee")
    h = hw.generate_key("p256", b"\x01" * 16, single_use=False)
    h.sign(b"a"); h.sign(b"b")
    assert hw.has_key(h.handle)


def test_key_is_not_exportable_or_copyable():
    _, hw = make()
    h = hw.generate_key("p256", b"\x01" * 16)
    with pytest.raises(HardwareError, match="exportável"):
        hw.export_key(h.handle)
    for fn in (copy.copy, copy.deepcopy):
        with pytest.raises(HardwareError):
            fn(hw)
    import pickle
    with pytest.raises(HardwareError):
        pickle.dumps(hw)


def test_cloned_app_state_cannot_sign_on_another_device():
    root, hw_a = make()
    hw_b = root.provision("strongbox", not_before=NOW - 100, not_after=NOW + 10**6, seed=b"\x99" * 32)
    h = hw_a.generate_key("p256", b"\x01" * 16)
    clone = type(h)(hw_b, h.handle, h.key_type, h.public_key, h.attestation)   # app copiado para outro aparelho
    with pytest.raises(HardwareError):
        clone.sign(b"m")


def test_restoring_an_app_backup_does_not_resurrect_a_used_key():
    _, hw = make()
    h = hw.generate_key("p256", b"\x01" * 16)
    backup = (h.handle, h.public_key, h.attestation)          # "backup" do estado do aplicativo
    h.sign(b"gasto")
    restored = type(h)(hw, backup[0], "p256", backup[1], backup[2])
    with pytest.raises(HardwareError):
        restored.sign(b"gasto-de-novo")                       # o hardware já apagou a chave


def test_broken_hardware_models_the_adversary():
    _, hw = make()
    h = hw.generate_key("p256", b"\x01" * 16)
    hw.break_single_use()
    s1, s2 = h.sign(b"a"), h.sign(b"b")
    assert s1 != s2 and hw.has_key(h.handle)                  # a atestação ainda "diz" uso único: risco residual (H1)


# ------------------------------------------------------------------ verificação da atestação
def test_untrusted_wrong_expired_revoked_and_mismatches():
    root, hw = make()
    h = hw.generate_key("p256", b"\x01" * 16)
    att = h.attestation
    with pytest.raises(ValidationError, match="não confiável"):
        verify_attestation(att, roots=[SimulatedRoot(seed=b"\x01" * 32).public_key], now=NOW)
    with pytest.raises(ValidationError, match="validade"):
        check(att, root, now=NOW + 10**7)                       # certificado do dispositivo expirado
    with pytest.raises(ValidationError, match="validade"):
        check(att, root, now=NOW - 10**6)                       # ainda não válido
    from winflux.crypto.hashing import sha256
    dev_id = sha256(bytes.fromhex(att["device"]["device_pubkey"])).hex()
    with pytest.raises(ValidationError, match="revogado"):
        check(att, root, revoked={dev_id})
    with pytest.raises(ValidationError, match="outra chave"):
        check(att, root, expect_pubkey="00" * 33)
    with pytest.raises(ValidationError, match="outro tipo"):
        check(att, root, expect_key_type="ed25519")
    with pytest.raises(ValidationError, match="desafio"):
        check(att, root, expect_challenge=(b"\x02" * 16).hex())


def test_key_level_above_device_maximum_is_rejected():
    root = SimulatedRoot(seed=b"\x42" * 32)
    hw = root.provision("tee", not_before=NOW - 100, not_after=NOW + 10**6)
    h = hw.generate_key("p256", b"\x01" * 16)
    att = copy.deepcopy(h.attestation)
    att["key"]["level"] = "strongbox"                            # o dispositivo só atesta até "tee"
    att["key_sig"] = hw._dev.sign(key_statement_bytes(att["key"])).hex()   # white-box: assinatura válida do dispositivo
    with pytest.raises(ValidationError, match="acima"):
        check(att, root)


def _paths(o, pre=()):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from _paths(v, pre + (k,))
    else:
        yield pre


def _get(o, p):
    for k in p:
        o = o[k]
    return o


def _set(o, p, v):
    for k in p[:-1]:
        o = o[k]
    o[p[-1]] = v


def _alt(v):
    if isinstance(v, bool):
        return not v
    if isinstance(v, int):
        return v + 1
    return v[:-1] + ("1" if v[-1] != "1" else "2") if isinstance(v, str) and v and all(c in "0123456789abcdef" for c in v) \
        else (v + "x" if isinstance(v, str) else None)


def test_every_attestation_field_is_bound():
    root, hw = make()
    base = hw.generate_key("p256", b"\x01" * 16).attestation
    check(base, root)
    n = 0
    for p in _paths(base):
        bad = copy.deepcopy(base)
        _set(bad, p, _alt(_get(base, p)))
        with pytest.raises(ValidationError):
            check(bad, root)
        n += 1
    assert n == len(list(_paths(base))) >= 15            # TODOS os campos adulterados


def test_attestation_fuzz_only_validation_errors():
    root, hw = make()
    base = hw.generate_key("p256", b"\x01" * 16).attestation
    rnd = random.Random(3)
    junk = [None, -1, 0, 2**70, "", "x", [], {}, True, 1.5, "00" * 32, [1], {"a": 1}, "g" * 64]
    for _ in range(2000):
        m = copy.deepcopy(base)
        for _ in range(rnd.choice([1, 2, 3])):
            _set(m, rnd.choice([p for p in _paths(m) if p]), copy.deepcopy(rnd.choice(junk)))
        try:
            check(m, root)
        except ValidationError:
            continue
        assert m == base
    for bad in (None, [], "x", {}, 5):
        with pytest.raises(ValidationError):
            check(bad, root)
