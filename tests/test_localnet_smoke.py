"""End-to-end smoke test on real PROCESSES (≈1 min). Off by default so the suite does not get longer:

    WINFLUX_SMOKE=1 python -m pytest tests/test_localnet_smoke.py -q
"""
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.mark.skipif(not os.environ.get("WINFLUX_SMOKE"), reason="set WINFLUX_SMOKE=1 to run (starts 5 processes)")
def test_smoke_script_passes_on_a_fresh_local_testnet():
    r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "smoke_test.py")], capture_output=True, text=True,
                       timeout=420, env=dict(os.environ, PYTHONPATH=ROOT))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "5/5 steps OK" in r.stdout
