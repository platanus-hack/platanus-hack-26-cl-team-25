import pytest

from .world import start, stop


@pytest.fixture()
def world(tmp_path):
    made = []

    def make(*a, **k):
        w = start(tmp_path, *a, **k)
        made.append(w)
        return w
    yield make
    for w in made:
        stop(w)
