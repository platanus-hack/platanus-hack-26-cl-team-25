"""The single implementation of parameter grammars (gateway, pipeline and tests use it).

A grammar is a full-match regex over the DECODED parameter value (after URL
decoding / JSON parsing; never the raw wire bytes). Python `re` dialect.
"""
from __future__ import annotations
import re

# Conservative default: letters, digits, space and a few harmless separators.
# No quotes, slashes, backslashes, parentheses, semicolons, percent, angle brackets.
SAFE_DEFAULT = r"[A-Za-z0-9 _.,@:+\-]{0,128}"


# For catch-all path parameters ({name*}): the default plus '/'. '..' stays unsafe (see matches).
PATH_SAFE = r"[A-Za-z0-9 _.,@:+\-/]{0,512}"


def matches(grammar: str, value: str) -> bool:
    """True if `value` is fully inside `grammar`. '..' is never safe."""
    if ".." in value:
        return False
    return re.fullmatch(grammar, value, flags=re.DOTALL) is not None


def is_safe_default(value: str) -> bool:
    return matches(SAFE_DEFAULT, value)
