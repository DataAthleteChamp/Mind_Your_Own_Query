"""
jpamb.taint

Variable-level taint tracking for SQL injection detection.

This module provides:
- TaintedValue: Core abstraction for tainted values
- TaintTransfer: Transfer functions for taint propagation
- SourceSinkDetector: Detection of sources and sinks

Example usage:
    >>> from jpamb.taint import TaintedValue, TaintTransfer
    >>> safe = TaintedValue.trusted("SELECT * FROM users WHERE id = ")
    >>> unsafe = TaintedValue.untrusted("1 OR 1=1")
    >>> query = TaintTransfer.concat(safe, unsafe)
    >>> query.is_tainted
    True
"""

from .value import TaintedValue, trusted, untrusted
from .transfer import TaintTransfer, concat
from .sources import SourceSinkDetector, UNTRUSTED_SOURCES, SQL_SINKS

__all__ = [
    "TaintedValue",
    "trusted",
    "untrusted",
    "TaintTransfer",
    "concat",
    "SourceSinkDetector",
    "UNTRUSTED_SOURCES",
    "SQL_SINKS",
]