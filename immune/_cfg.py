"""Config access for the installer (init / doctor / deploy).

P1's `immune.config` is the loader (contracts/product.md §2). This module only adds the
installer's own path conventions on top of it, so that swapping the loader never
touches init/doctor code.
"""
from __future__ import annotations

import os

from immune.config import (IMMUNE_HOME, CONTAINER_APP, CONTAINER_HOME, Config, ConfigError,  # noqa: F401
                           from_dict, load)

DOT = ".immune"
DEFAULT_COLUMNS = os.path.join(DOT, "shadow", "columns.yaml")
DEFAULT_PROFILE_MODULE = "profile"          # <project>/.immune/profile.py


def dot(project: str, *parts) -> str:
    return os.path.join(os.path.realpath(project), DOT, *parts)


def columns_path(cfg: Config) -> str:
    return cfg.shadow.columns or os.path.join(cfg.project_dir, DEFAULT_COLUMNS)


def shadow_markers_path(cfg: Config) -> str:
    return os.path.join(cfg.shadow_dir, "markers.json")
