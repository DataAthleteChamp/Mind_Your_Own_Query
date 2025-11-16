"""
jpamb.taint.transfer

Transfer functions for taint propagation through string operations.

These functions define how taint flows through various string operations.
In variable-level taint tracking:
- If ANY input is tainted, the output is tainted
- Only fully trusted inputs produce trusted outputs
"""

from typing import List, Optional
from .value import TaintedValue


class TaintTransfer:
    """
    Transfer functions for string operations with taint propagation.

    These functions implement the rules for how taint flows through
    string operations in variable-level analysis.
    """

    @staticmethod
    def concat(*values: TaintedValue) -> TaintedValue:
        """
        String concatenation: output is tainted if ANY input is tainted.

        This is conservative - we assume that any taint "infects" the result.
        For SQL injection, this is the correct behavior: if any part of a
        query comes from user input, the whole query is vulnerable.

        Args:
            *values: One or more TaintedValues to concatenate

        Returns:
            TaintedValue with concatenated value and propagated taint

        Example:
            >>> safe = TaintedValue.trusted("SELECT * FROM users WHERE id = ")
            >>> unsafe = TaintedValue.untrusted("1 OR 1=1")
            >>> result = TaintTransfer.concat(safe, unsafe)
            >>> result.is_tainted
            True
            >>> result.value
            'SELECT * FROM users WHERE id = 1 OR 1=1'
        """
        # Concatenate all values
        result_value = "".join(str(v.value) for v in values)

        # Output is tainted if ANY input is tainted
        is_tainted = any(v.is_tainted for v in values)

        # Track all taint sources
        sources = [v.source for v in values if v.is_tainted]
        source = ", ".join(sources) if sources else "literal"

        return TaintedValue(result_value, is_tainted, source)

    @staticmethod
    def substring(
        value: TaintedValue, start: int, end: Optional[int] = None
    ) -> TaintedValue:
        """
        Substring extraction: preserves taint.

        Taking a substring of a tainted string does NOT sanitize it.
        The substring is still tainted because it came from untrusted source.

        Args:
            value: The TaintedValue to extract from
            start: Starting index
            end: Ending index (None = to end of string)

        Returns:
            TaintedValue with extracted substring, taint preserved

        Example:
            >>> tainted = TaintedValue.untrusted("admin' OR '1'='1")
            >>> substr = TaintTransfer.substring(tainted, 0, 5)
            >>> substr.value
            'admin'
            >>> substr.is_tainted  # Still tainted!
            True
        """
        str_value = str(value.value)
        if end is None:
            result_value = str_value[start:]
        else:
            result_value = str_value[start:end]

        # Substring preserves taint
        return TaintedValue(result_value, value.is_tainted, value.source)

    @staticmethod
    def replace(
        value: TaintedValue, old: str, new: str
    ) -> TaintedValue:
        """
        String replacement: preserves taint.

        Replacing characters in a tainted string does NOT sanitize it.
        Even SQL escaping (e.g., ' -> '') doesn't make user input safe.

        Args:
            value: The TaintedValue to perform replacement on
            old: Substring to find
            new: Substring to replace with

        Returns:
            TaintedValue with replaced string, taint preserved

        Example:
            >>> tainted = TaintedValue.untrusted("admin'")
            >>> escaped = TaintTransfer.replace(tainted, "'", "''")
            >>> escaped.value
            "admin''"
            >>> escaped.is_tainted  # Still tainted! SQL escaping doesn't sanitize
            True
        """
        result_value = str(value.value).replace(old, new)

        # Replace preserves taint (escaping doesn't sanitize!)
        return TaintedValue(result_value, value.is_tainted, value.source)

    @staticmethod
    def trim(value: TaintedValue) -> TaintedValue:
        """
        Trim whitespace: preserves taint.

        Args:
            value: The TaintedValue to trim

        Returns:
            TaintedValue with trimmed string, taint preserved

        Example:
            >>> tainted = TaintedValue.untrusted("  malicious  ")
            >>> trimmed = TaintTransfer.trim(tainted)
            >>> trimmed.value
            'malicious'
            >>> trimmed.is_tainted
            True
        """
        result_value = str(value.value).strip()
        return TaintedValue(result_value, value.is_tainted, value.source)

    @staticmethod
    def to_lower(value: TaintedValue) -> TaintedValue:
        """
        Convert to lowercase: preserves taint.

        Args:
            value: The TaintedValue to convert

        Returns:
            TaintedValue with lowercase string, taint preserved
        """
        result_value = str(value.value).lower()
        return TaintedValue(result_value, value.is_tainted, value.source)

    @staticmethod
    def to_upper(value: TaintedValue) -> TaintedValue:
        """
        Convert to uppercase: preserves taint.

        Args:
            value: The TaintedValue to convert

        Returns:
            TaintedValue with uppercase string, taint preserved
        """
        result_value = str(value.value).upper()
        return TaintedValue(result_value, value.is_tainted, value.source)

    @staticmethod
    def split(
        value: TaintedValue, delimiter: str
    ) -> List[TaintedValue]:
        """
        Split string: all parts inherit taint.

        Args:
            value: The TaintedValue to split
            delimiter: String to split on

        Returns:
            List of TaintedValues, each with same taint as original

        Example:
            >>> tainted = TaintedValue.untrusted("admin,user,guest")
            >>> parts = TaintTransfer.split(tainted, ",")
            >>> [p.value for p in parts]
            ['admin', 'user', 'guest']
            >>> all(p.is_tainted for p in parts)
            True
        """
        parts = str(value.value).split(delimiter)
        return [
            TaintedValue(part, value.is_tainted, value.source)
            for part in parts
        ]

    @staticmethod
    def join(
        delimiter: TaintedValue, values: List[TaintedValue]
    ) -> TaintedValue:
        """
        Join strings: tainted if delimiter OR any value is tainted.

        Args:
            delimiter: TaintedValue to use as separator
            values: List of TaintedValues to join

        Returns:
            TaintedValue with joined string

        Example:
            >>> safe_delim = TaintedValue.trusted(",")
            >>> parts = [TaintedValue.untrusted("admin"), TaintedValue.trusted("user")]
            >>> result = TaintTransfer.join(safe_delim, parts)
            >>> result.value
            'admin,user'
            >>> result.is_tainted  # Tainted because one part is tainted
            True
        """
        delimiter_str = str(delimiter.value)
        value_strs = [str(v.value) for v in values]
        result_value = delimiter_str.join(value_strs)

        # Tainted if delimiter OR any value is tainted
        is_tainted = delimiter.is_tainted or any(
            v.is_tainted for v in values
        )

        # Collect sources
        sources = []
        if delimiter.is_tainted:
            sources.append(delimiter.source)
        sources.extend(v.source for v in values if v.is_tainted)
        source = ", ".join(sources) if sources else "literal"

        return TaintedValue(result_value, is_tainted, source)


# Convenience function for common concat pattern
def concat(*values: TaintedValue) -> TaintedValue:
    """Shorthand for TaintTransfer.concat()"""
    return TaintTransfer.concat(*values)
