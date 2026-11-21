"""Release consistency: single version, entry points and promised documents exist."""
import os
import re

import winflux

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_version_is_single_sourced_and_exposed():
    py = open(os.path.join(ROOT, "pyproject.toml")).read()
    assert re.search(r'^version = "%s"$' % re.escape(winflux.__version__), py, re.M)
    assert winflux.__version__ in open(os.path.join(ROOT, "CHANGELOG.md")).read()


def test_console_entry_points_resolve():
    import importlib
    py = open(os.path.join(ROOT, "pyproject.toml")).read()
    for mod, fn in re.findall(r'^winflux-\w+ = "([\w.]+):(\w+)"$', py, re.M):
        assert callable(getattr(importlib.import_module(mod), fn)), (mod, fn)


def test_docs_linked_from_readme_exist():
    readme = open(os.path.join(ROOT, "README.md")).read()
    for path in set(re.findall(r"`(docs/[\w\-]+\.md)`", readme)):
        assert os.path.exists(os.path.join(ROOT, path)), path
    for path in ("scripts/run_local_testnet.py", "scripts/smoke_test.py", "docs/test-plan.md", "CHANGELOG.md"):
        assert os.path.exists(os.path.join(ROOT, path)), path
