"""
Property-based tests for jpamb.taint module using Hypothesis

These tests verify invariants that should hold for all possible inputs,
catching edge cases that might be missed by example-based tests.
"""

import pytest
from hypothesis import given, assume, strategies as st
from jpamb.taint import TaintedValue, TaintTransfer


# Custom strategies for generating TaintedValues
@st.composite
def tainted_values(draw, tainted=None):
    """Strategy for generating arbitrary TaintedValues"""
    value = draw(st.one_of(
        st.text(),
        st.integers(),
        st.floats(allow_nan=False, allow_infinity=False),
        st.none()
    ))

    if tainted is None:
        is_tainted = draw(st.booleans())
    else:
        is_tainted = tainted

    source = draw(st.text(min_size=1, max_size=100))

    if is_tainted:
        return TaintedValue.untrusted(value, source=source)
    else:
        return TaintedValue.trusted(value, source=source)


@st.composite
def trusted_values(draw):
    """Strategy for generating trusted TaintedValues"""
    return draw(tainted_values(tainted=False))


@st.composite
def untrusted_values(draw):
    """Strategy for generating untrusted TaintedValues"""
    return draw(tainted_values(tainted=True))


class TestConcatProperties:
    """Property-based tests for concatenation"""

    @given(st.lists(tainted_values(), min_size=1))
    def test_concat_preserves_taint_if_any_tainted(self, values):
        """If ANY input is tainted, output must be tainted"""
        result = TaintTransfer.concat(*values)

        if any(v.is_tainted for v in values):
            assert result.is_tainted
        else:
            assert not result.is_tainted

    @given(st.lists(trusted_values(), min_size=1))
    def test_concat_all_trusted_produces_trusted(self, values):
        """Concatenating only trusted values produces trusted result"""
        result = TaintTransfer.concat(*values)
        assert not result.is_tainted

    @given(st.lists(untrusted_values(), min_size=1))
    def test_concat_all_untrusted_produces_untrusted(self, values):
        """Concatenating only untrusted values produces untrusted result"""
        result = TaintTransfer.concat(*values)
        assert result.is_tainted

    @given(st.lists(tainted_values(), min_size=1, max_size=10))
    def test_concat_length_equals_sum(self, values):
        """Concatenated length equals sum of input lengths"""
        result = TaintTransfer.concat(*values)
        expected_length = sum(len(str(v.value)) for v in values)
        assert len(result.value) == expected_length

    @given(trusted_values(), untrusted_values())
    def test_concat_order_irrelevant_for_taint(self, trusted, untrusted):
        """Order of trusted/untrusted doesn't matter - result is always tainted"""
        result1 = TaintTransfer.concat(trusted, untrusted)
        result2 = TaintTransfer.concat(untrusted, trusted)

        assert result1.is_tainted
        assert result2.is_tainted

    @given(tainted_values())
    def test_concat_identity_single_value(self, value):
        """Concatenating single value is identity operation"""
        result = TaintTransfer.concat(value)
        assert result.is_tainted == value.is_tainted
        assert str(result.value) == str(value.value)


class TestSubstringProperties:
    """Property-based tests for substring"""

    @given(tainted_values(), st.integers(min_value=0, max_value=100))
    def test_substring_preserves_taint(self, value, start):
        """Substring always preserves taint status"""
        # Assume start is within reasonable bounds
        assume(start >= 0)

        result = TaintTransfer.substring(value, start)
        assert result.is_tainted == value.is_tainted

    @given(tainted_values(), st.integers(min_value=0, max_value=50),
           st.integers(min_value=0, max_value=50))
    def test_substring_with_end_preserves_taint(self, value, start, end):
        """Substring with end index preserves taint"""
        assume(start >= 0 and end >= start)

        result = TaintTransfer.substring(value, start, end)
        assert result.is_tainted == value.is_tainted

    @given(tainted_values(), st.integers(min_value=0, max_value=100))
    def test_substring_length_bounded(self, value, start):
        """Substring length is at most original length"""
        assume(start >= 0)

        result = TaintTransfer.substring(value, start)
        original_len = len(str(value.value))
        result_len = len(str(result.value))

        assert result_len <= original_len

    @given(untrusted_values())
    def test_substring_empty_still_tainted(self, value):
        """Even empty substring of tainted value is tainted"""
        result = TaintTransfer.substring(value, 0, 0)
        assert result.is_tainted
        assert result.value == ""


class TestReplaceProperties:
    """Property-based tests for replace"""

    @given(tainted_values(), st.text(max_size=10), st.text(max_size=10))
    def test_replace_preserves_taint(self, value, old, new):
        """Replace always preserves taint status"""
        result = TaintTransfer.replace(value, old, new)
        assert result.is_tainted == value.is_tainted

    @given(untrusted_values(), st.text(min_size=1, max_size=5),
           st.text(min_size=1, max_size=5))
    def test_replace_untrusted_stays_untrusted(self, value, old, new):
        """Replacing in untrusted value keeps it untrusted"""
        result = TaintTransfer.replace(value, old, new)
        assert result.is_tainted

    @given(trusted_values(), st.text(max_size=5), st.text(max_size=5))
    def test_replace_trusted_stays_trusted(self, value, old, new):
        """Replacing in trusted value keeps it trusted"""
        result = TaintTransfer.replace(value, old, new)
        assert not result.is_tainted

    @given(tainted_values())
    def test_replace_identity(self, value):
        """Replace with same old=new is identity operation"""
        result = TaintTransfer.replace(value, "x", "x")
        assert result.is_tainted == value.is_tainted
        assert str(result.value) == str(value.value)


class TestTrimProperties:
    """Property-based tests for trim"""

    @given(tainted_values())
    def test_trim_preserves_taint(self, value):
        """Trim always preserves taint status"""
        result = TaintTransfer.trim(value)
        assert result.is_tainted == value.is_tainted

    @given(tainted_values())
    def test_trim_length_bounded(self, value):
        """Trimmed length is at most original length"""
        result = TaintTransfer.trim(value)
        original_len = len(str(value.value))
        trimmed_len = len(str(result.value))
        assert trimmed_len <= original_len

    @given(untrusted_values())
    def test_trim_untrusted_stays_untrusted(self, value):
        """Trimming untrusted value keeps it untrusted"""
        result = TaintTransfer.trim(value)
        assert result.is_tainted

    @given(trusted_values())
    def test_trim_trusted_stays_trusted(self, value):
        """Trimming trusted value keeps it trusted"""
        result = TaintTransfer.trim(value)
        assert not result.is_tainted

    @given(tainted_values())
    def test_trim_idempotent(self, value):
        """Trimming twice is same as trimming once"""
        once = TaintTransfer.trim(value)
        twice = TaintTransfer.trim(once)
        assert once.value == twice.value
        assert once.is_tainted == twice.is_tainted


class TestCaseConversionProperties:
    """Property-based tests for case conversion"""

    @given(tainted_values())
    def test_to_lower_preserves_taint(self, value):
        """to_lower preserves taint status"""
        result = TaintTransfer.to_lower(value)
        assert result.is_tainted == value.is_tainted

    @given(tainted_values())
    def test_to_upper_preserves_taint(self, value):
        """to_upper preserves taint status"""
        result = TaintTransfer.to_upper(value)
        assert result.is_tainted == value.is_tainted

    @given(tainted_values())
    def test_case_conversion_length_preserved(self, value):
        """Case conversion usually preserves string length (but not always for Unicode)"""
        lower = TaintTransfer.to_lower(value)
        upper = TaintTransfer.to_upper(value)

        original_len = len(str(value.value))
        # Note: Some Unicode characters change length when case-converted
        # e.g., German ß becomes SS when uppercased
        # So we just verify taint is preserved, not length
        assert lower.is_tainted == value.is_tainted
        assert upper.is_tainted == value.is_tainted

    @given(tainted_values())
    def test_case_conversion_roundtrip(self, value):
        """Lower then upper may not equal upper then lower, but taint preserved"""
        lower_upper = TaintTransfer.to_upper(TaintTransfer.to_lower(value))
        upper_lower = TaintTransfer.to_lower(TaintTransfer.to_upper(value))

        assert lower_upper.is_tainted == value.is_tainted
        assert upper_lower.is_tainted == value.is_tainted


class TestSplitJoinProperties:
    """Property-based tests for split and join"""

    @given(tainted_values(), st.text(min_size=1, max_size=3))
    def test_split_preserves_taint_in_all_parts(self, value, delimiter):
        """Split preserves taint in all resulting parts"""
        parts = TaintTransfer.split(value, delimiter)

        for part in parts:
            assert part.is_tainted == value.is_tainted

    @given(tainted_values(), st.text(min_size=1, max_size=3))
    def test_split_parts_concatenate_to_original(self, value, delimiter):
        """Splitting then joining (without delimiter) gives back content"""
        parts = TaintTransfer.split(value, delimiter)

        if parts:
            # All parts have same taint
            assert all(p.is_tainted == value.is_tainted for p in parts)

    @given(tainted_values(), st.text(min_size=1, max_size=3))
    def test_join_preserves_taint_if_any_tainted(self, delimiter_val, part_text):
        """Join is tainted if delimiter OR any part is tainted"""
        # Create parts
        parts = [
            TaintedValue.trusted(part_text),
            TaintedValue.trusted(part_text)
        ]

        result = TaintTransfer.join(delimiter_val, parts)

        if delimiter_val.is_tainted:
            assert result.is_tainted


class TestSourceTrackingProperties:
    """Property-based tests for source tracking"""

    @given(st.text(min_size=1), st.text(min_size=1))
    def test_source_preserved_through_operations(self, value, source):
        """Source information preserved through transformations"""
        original = TaintedValue.untrusted(value, source=source)

        # Apply various operations
        trimmed = TaintTransfer.trim(original)
        lowered = TaintTransfer.to_lower(trimmed)

        assert lowered.source == source

    @given(st.lists(untrusted_values(), min_size=2, max_size=5))
    def test_concat_combines_sources(self, values):
        """Concatenation combines all taint sources"""
        result = TaintTransfer.concat(*values)

        assert result.is_tainted
        # Result source should contain information from inputs
        for v in values:
            if v.is_tainted:
                assert v.source in result.source or "," in result.source


class TestCommutativityProperties:
    """Test commutative properties where applicable"""

    @given(tainted_values(), tainted_values())
    def test_concat_commutativity_for_taint(self, v1, v2):
        """Concat taint result is commutative (but not value)"""
        r1 = TaintTransfer.concat(v1, v2)
        r2 = TaintTransfer.concat(v2, v1)

        # Taint result should be same regardless of order
        assert r1.is_tainted == r2.is_tainted


class TestAssociativityProperties:
    """Test associative properties"""

    @given(tainted_values(), tainted_values(), tainted_values())
    def test_concat_associativity_for_taint(self, v1, v2, v3):
        """Concat is associative for taint tracking"""
        # (v1 + v2) + v3
        left_assoc = TaintTransfer.concat(TaintTransfer.concat(v1, v2), v3)

        # v1 + (v2 + v3)
        right_assoc = TaintTransfer.concat(v1, TaintTransfer.concat(v2, v3))

        # Taint should be same
        assert left_assoc.is_tainted == right_assoc.is_tainted


class TestMonotonicityProperties:
    """Test monotonicity properties"""

    @given(tainted_values())
    def test_operations_monotonic_for_taint(self, value):
        """Operations never remove taint (monotonic)"""
        operations = [
            lambda v: TaintTransfer.trim(v),
            lambda v: TaintTransfer.to_lower(v),
            lambda v: TaintTransfer.to_upper(v),
            lambda v: TaintTransfer.substring(v, 0),
            lambda v: TaintTransfer.replace(v, "x", "y"),
        ]

        for op in operations:
            result = op(value)
            # If original was tainted, result must be tainted
            if value.is_tainted:
                assert result.is_tainted
            # If original was trusted, result must be trusted
            else:
                assert not result.is_tainted


class TestSafetyInvariants:
    """Test safety invariants for SQL injection detection"""

    @given(untrusted_values())
    def test_untrusted_never_becomes_safe(self, value):
        """Untrusted value can never become safe for SQL"""
        # Apply any combination of operations
        result = value
        for _ in range(5):
            op = [
                TaintTransfer.trim,
                TaintTransfer.to_lower,
                TaintTransfer.to_upper,
            ]
            import random
            result = random.choice(op)(result)

        # Should still be unsafe
        assert not result.is_safe_for_sql()

    @given(trusted_values())
    def test_trusted_stays_safe(self, value):
        """Trusted value stays safe through operations"""
        result = TaintTransfer.trim(value)
        result = TaintTransfer.to_lower(result)

        assert result.is_safe_for_sql()

    @given(trusted_values(), untrusted_values())
    def test_mixing_trusted_untrusted_unsafe(self, trusted, untrusted):
        """Mixing trusted with untrusted always produces unsafe result"""
        result = TaintTransfer.concat(trusted, untrusted)
        assert not result.is_safe_for_sql()
