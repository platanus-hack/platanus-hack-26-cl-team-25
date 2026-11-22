"""Patcher: LLM fix author (confined Claude Code), plan-B fixes, variants, rules.

Interface: contracts/interfaces.md.
"""
from .core import propose
from .rule import derive_rule
from .variants import variants

__all__ = ["propose", "variants", "derive_rule"]
