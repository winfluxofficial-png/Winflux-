"""Smoke test de ponta a ponta em PROCESSOS reais (≈1 min). Desligado por padrão para não alongar a suíte:

    WINFLUX_SMOKE=1 python -m pytest tests/test_localnet_smoke.py -q
"""
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.mark.skipif(not os.environ.get("WINFLUX_SMOKE"), reason="defina WINFLUX_SMOKE=1 para rodar (sobe 5 processos)")
def test_smoke_script_passes_on_a_fresh_local_testnet():
    r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "smoke_test.py")], capture_output=True, text=True,
                       timeout=420, env=dict(os.environ, PYTHONPATH=ROOT))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "5/5 passos OK" in r.stdout
