"""Shared contract code: token format, parameter grammars, clone wire protocol, event types.

Every component imports these helpers instead of re-implementing them, so that
two packages can never disagree on a wire format. Reference: contracts/README.md.
"""
