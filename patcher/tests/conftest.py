import os
import sys

import pytest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(HERE, "fixtures"))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from incidents import all_incidents  # noqa: E402


def pytest_configure(config):
    config.addinivalue_line("markers", "live: calls the real Claude Code CLI (deselect with -m 'not live')")


@pytest.fixture(scope="session")
def t0_release():
    """A release dir holding the t0 code (read-only; propose only copies victim/ out of it)."""
    p = os.path.join(REPO, "runtime", "releases", "t0")
    return p if os.path.isdir(os.path.join(p, "victim")) else REPO


@pytest.fixture(scope="session")
def incidents():
    return all_incidents()


@pytest.fixture(scope="session")
def openapi():
    with open(os.path.join(REPO, "contracts", "openapi.yaml")) as f:
        return yaml.safe_load(f)
