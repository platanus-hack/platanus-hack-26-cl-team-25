import json
import os
import shutil
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
FIX = os.path.join(HERE, "fixtures")


def load_fixture(name):
    with open(os.path.join(FIX, name)) as f:
        return json.load(f)


@pytest.fixture(scope="session")
def spec():
    from pipeline import openapi
    return openapi.load(os.path.join(ROOT, "contracts", "openapi.yaml"))


@pytest.fixture()
def t0(tmp_path):
    """A release dir with a pristine copy of the repo's victim/ (== t0)."""
    d = tmp_path / "t0"
    shutil.copytree(os.path.join(ROOT, "victim"), d / "victim", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return str(d)


@pytest.fixture()
def events():
    return {k: load_fixture("oracle_%s.json" % k) for k in ("sqli", "traversal", "idor")}
