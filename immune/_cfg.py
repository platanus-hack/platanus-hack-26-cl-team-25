"""Config access for the installer (init / doctor / deploy).

`immune.config` is the loader (contracts/product.md §2). This module only adds the
installer's own path conventions on top of it, so that swapping the loader never
touches init/doctor code.
"""
from __future__ import annotations

import os

from immune.config import IMMUNE_HOME, CONTAINER_APP, CONTAINER_HOME, Config, load

__all__ = ["IMMUNE_HOME", "CONTAINER_APP", "CONTAINER_HOME", "Config", "load", "DOT", "DEFAULT_COLUMNS",
           "DEFAULT_PROFILE_MODULE", "columns_path", "shadow_markers_path"]

DOT = ".immune"
DEFAULT_COLUMNS = os.path.join(DOT, "shadow", "columns.yaml")
DEFAULT_PROFILE_MODULE = "profile"          # <project>/.immune/profile.py


def columns_path(cfg: Config) -> str:
    return cfg.shadow.columns or os.path.join(cfg.project_dir, DEFAULT_COLUMNS)


def shadow_markers_path(cfg: Config) -> str:
    return os.path.join(cfg.shadow_dir, "markers.json")
