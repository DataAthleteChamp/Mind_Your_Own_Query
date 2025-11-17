"""
jpamb.taint.value

Variable-level taint tracking for SQL injection detection.

This module provides the TaintedValue abstraction for tracking whether
a value originated from a trusted or untrusted source. Unlike character-level
taint tracking (which uses bit-vectors per character), variable-level tracking
uses a single boolean flag per value.

This is simpler to implement while still effective for SQL injection detection.
"""

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class TaintedValue:
    """
    A value with variable-level taint tracking.

    In variable-level taint analysis, we track whether an entire value
    is tainted (from untrusted source) or trusted (from literal/safe source).

    Attributes:
        value: The actual value (string, int, etc.)
        is_tainted: True if value came from untrusted source
        source: Description of where the taint originated

    Example:
        >>> trusted = TaintedValue.trusted("SELECT * FROM users")
        >>> trusted.is_tainted
        False

        >>> untrusted = TaintedValue.untrusted("admin' OR '1'='1")
        >>> untrusted.is_tainted
        True
    """

    value: Any
    is_tainted: bool
    source: str = "unknown"

    def __repr__(self) -> str:
        """String representation with taint indicator"""
        taint_mark = "⚠️" if self.is_tainted else "✓"
        return f"{taint_mark} {self.value!r} (from {self.source})"

    def __str__(self) -> str:
        """Display value with taint status"""
        return f"{self.value} [{'TAINTED' if self.is_tainted else 'TRUSTED'}]"

    @classmethod
    def trusted(cls, value: Any, source: str = "literal") -> "TaintedValue":
        """
        Create a trusted (safe) value.

        Args:
            value: The value to wrap
            source: Where this trusted value came from (default: "literal")

        Returns:
            TaintedValue with is_tainted=False

        Example:
            >>> query_base = TaintedValue.trusted("SELECT * FROM users WHERE id = ")
            >>> query_base.is_tainted
            False
        """
        return cls(value, is_tainted=False, source=source)

    @classmethod
    def untrusted(
        cls, value: Any, source: str = "user_input"
    ) -> "TaintedValue":
        """
        Create an untrusted (tainted) value.

        Args:
            value: The value to wrap
            source: Where this untrusted value came from (default: "user_input")

        Returns:
            TaintedValue with is_tainted=True

        Example:
            >>> user_id = TaintedValue.untrusted("1 OR 1=1", source="http_param")
            >>> user_id.is_tainted
            True
            >>> user_id.source
            'http_param'
        """
        return cls(value, is_tainted=True, source=source)

    def is_safe_for_sql(self) -> bool:
        """
        Check if this value is safe to use in SQL query.

        Returns:
            True if value is fully trusted (not tainted)

        Example:
            >>> TaintedValue.trusted("SELECT *").is_safe_for_sql()
            True
            >>> TaintedValue.untrusted("'; DROP TABLE users--").is_safe_for_sql()
            False
        """
        return not self.is_tainted

    def get_string_value(self) -> str:
        """
        Get the underlying value as a string.

        Returns:
            String representation of the value
        """
        return str(self.value)


# Convenience functions for common patterns
def trusted(value: Any, source: str = "literal") -> TaintedValue:
    """Shorthand for TaintedValue.trusted()"""
    return TaintedValue.trusted(value, source)


def untrusted(value: Any, source: str = "user_input") -> TaintedValue:
    """Shorthand for TaintedValue.untrusted()"""
    return TaintedValue.untrusted(value, source)
