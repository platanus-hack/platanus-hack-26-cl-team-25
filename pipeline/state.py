"""Persistent pipeline state (<runtime>/pipeline/state.json), atomic writes, survives restarts."""
from __future__ import annotations

import json
import os
import threading
import time


class State:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.RLock()
        self.data = {"version": 1, "last_seq": 0, "counter": 0, "current_release": None,
                     "incidents": {}, "queue": [], "keys": {}}
        self._dirty_since = None
        if os.path.exists(path):
            with open(path) as f:
                self.data.update(json.load(f))

    def save(self) -> None:
        with self.lock:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self.data, f, default=str)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
            self._dirty_since = None

    def touch_seq(self, seq: int, force: bool = False) -> None:
        """Record the last bus seq; persisted at most once a second unless forced."""
        with self.lock:
            if seq > self.data["last_seq"]:
                self.data["last_seq"] = seq
            now = time.time()
            if self._dirty_since is None:
                self._dirty_since = now
            if force or now - self._dirty_since >= 1.0:
                self.save()

    def flush(self) -> None:
        with self.lock:
            if self._dirty_since is not None:
                self.save()

    # ---------------------------------------------------------------- incidents
    def new_id(self) -> str:
        with self.lock:
            self.data["counter"] += 1
            return "inc-%04d" % self.data["counter"]

    def incident(self, iid: str) -> dict:
        return self.data["incidents"][iid]

    def update(self, iid: str, **kw) -> dict:
        with self.lock:
            self.data["incidents"][iid].update(kw)
            self.save()
            return self.data["incidents"][iid]
