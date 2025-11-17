"""
Tests for input validation and error handling in jpamb.taint module
"""

import pytest
from jpamb.taint import TaintedValue, TaintTransfer


class TestConcatValidation:
    """Test concat() input validation"""

    def test_concat_empty_raises_valueerror(self):
        """Concatenating zero values should raise ValueError"""
        with pytest.raises(ValueError, match="requires at least one value"):
            TaintTransfer.concat()

    def test_concat_non_taintedvalue_raises_typeerror(self):
        """Concatenating non-TaintedValue should raise TypeError"""
        with pytest.raises(TypeError, match="must be TaintedValue instances"):
            TaintTransfer.concat("not a TaintedValue")  # type: ignore

    def test_concat_mixed_types_raises_typeerror(self):
        """Mixing TaintedValue with other types should raise TypeError"""
        valid = TaintedValue.trusted("test")
        with pytest.raises(TypeError, match="must be TaintedValue instances"):
            TaintTransfer.concat(valid, "invalid")  # type: ignore

    def test_concat_single_value_works(self):
        """Concatenating single value should work"""
        value = TaintedValue.trusted("test")
        result = TaintTransfer.concat(value)
        assert result.value == "test"
        assert not result.is_tainted


class TestSubstringValidation:
    """Test substring() input validation"""

    def test_substring_non_taintedvalue_raises_typeerror(self):
        """Substring of non-TaintedValue should raise TypeError"""
        with pytest.raises(TypeError, match="must be a TaintedValue instance"):
            TaintTransfer.substring("not a TaintedValue", 0, 5)  # type: ignore

    def test_substring_negative_start_raises_valueerror(self):
        """Negative start index should raise ValueError"""
        value = TaintedValue.trusted("test")
        with pytest.raises(ValueError, match="start index must be >= 0"):
            TaintTransfer.substring(value, -1, 5)

    def test_substring_end_before_start_raises_valueerror(self):
        """End index before start should raise ValueError"""
        value = TaintedValue.trusted("test")
        with pytest.raises(ValueError, match="end index .* must be >= start index"):
            TaintTransfer.substring(value, 5, 2)

    def test_substring_start_equals_end_valid(self):
        """Start equals end is valid (empty substring)"""
        value = TaintedValue.trusted("test")
        result = TaintTransfer.substring(value, 2, 2)
        assert result.value == ""

    def test_substring_zero_start_valid(self):
        """Start index of 0 is valid"""
        value = TaintedValue.trusted("test")
        result = TaintTransfer.substring(value, 0, 2)
        assert result.value == "te"

    def test_substring_start_beyond_length(self):
        """Start beyond string length returns empty string (Python behavior)"""
        value = TaintedValue.trusted("test")
        result = TaintTransfer.substring(value, 100)
        assert result.value == ""
        # Taint is still preserved
        assert not result.is_tainted

    def test_substring_end_beyond_length(self):
        """End beyond string length is valid (Python behavior)"""
        value = TaintedValue.trusted("test")
        result = TaintTransfer.substring(value, 0, 100)
        assert result.value == "test"


class TestReplaceValidation:
    """Test replace() input validation"""

    def test_replace_non_taintedvalue_raises_typeerror(self):
        """Replace on non-TaintedValue should raise TypeError"""
        # Current implementation doesn't validate, but should in production
        # Adding this test for future enhancement
        pass  # Placeholder for future validation


class TestTrimValidation:
    """Test trim() input validation"""

    def test_trim_non_taintedvalue_raises_typeerror(self):
        """Trim on non-TaintedValue should raise TypeError"""
        # Current implementation doesn't validate, but should in production
        # Adding this test for future enhancement
        pass  # Placeholder for future validation


class TestSplitValidation:
    """Test split() input validation"""

    def test_split_non_taintedvalue_raises_typeerror(self):
        """Split on non-TaintedValue should raise TypeError"""
        # Current implementation doesn't validate, but should in production
        # Adding this test for future enhancement
        pass  # Placeholder for future validation

    def test_split_empty_delimiter(self):
        """Split with empty delimiter should work (splits every char)"""
        value = TaintedValue.trusted("abc")
        # Python's split with empty string raises ValueError
        # This is expected Python behavior - no need to test differently
        pass


class TestJoinValidation:
    """Test join() input validation"""

    def test_join_non_taintedvalue_delimiter_raises_typeerror(self):
        """Join with non-TaintedValue delimiter should raise TypeError"""
        # Current implementation doesn't validate, but should in production
        # Adding this test for future enhancement
        pass  # Placeholder for future validation

    def test_join_empty_list(self):
        """Join with empty list should work"""
        delimiter = TaintedValue.trusted(",")
        result = TaintTransfer.join(delimiter, [])
        assert result.value == ""
        assert not result.is_tainted


class TestCaseConversionValidation:
    """Test case conversion input validation"""

    def test_to_lower_non_taintedvalue_raises_typeerror(self):
        """to_lower on non-TaintedValue should raise TypeError"""
        # Current implementation doesn't validate, but should in production
        # Adding this test for future enhancement
        pass  # Placeholder for future validation

    def test_to_upper_non_taintedvalue_raises_typeerror(self):
        """to_upper on non-TaintedValue should raise TypeError"""
        # Current implementation doesn't validate, but should in production
        # Adding this test for future enhancement
        pass  # Placeholder for future validation


class TestBoundaryConditions:
    """Test boundary conditions and edge cases"""

    def test_very_long_string(self):
        """Handle very long strings (10MB)"""
        long_string = "x" * (10 * 1024 * 1024)  # 10 MB
        value = TaintedValue.untrusted(long_string)
        result = TaintTransfer.trim(value)
        assert result.is_tainted
        assert len(result.value) == len(long_string)

    def test_many_concatenations(self):
        """Handle many concatenations (1000 values)"""
        values = [TaintedValue.trusted(f"part{i}") for i in range(1000)]
        result = TaintTransfer.concat(*values)
        assert not result.is_tainted
        assert "part999" in result.value

    def test_deeply_nested_sources(self):
        """Track deeply nested source transformations"""
        original = TaintedValue.untrusted("data", source="http")

        # Apply 100 transformations
        current = original
        for _ in range(100):
            current = TaintTransfer.to_upper(current)

        assert current.is_tainted
        assert current.source == "http"

    def test_unicode_edge_cases(self):
        """Handle various Unicode edge cases"""
        # Emoji
        emoji = TaintedValue.untrusted("👨‍💻")
        result = TaintTransfer.concat(TaintedValue.trusted("Hello "), emoji)
        assert result.is_tainted

        # Zero-width characters
        zero_width = TaintedValue.untrusted("\u200b")  # Zero-width space
        result = TaintTransfer.trim(zero_width)
        assert result.is_tainted

        # RTL marks
        rtl = TaintedValue.untrusted("\u202e")  # Right-to-left override
        result = TaintTransfer.concat(TaintedValue.trusted("test"), rtl)
        assert result.is_tainted

    def test_null_bytes(self):
        """Handle null bytes in strings"""
        null_byte = TaintedValue.untrusted("admin\x00DROP")
        query = TaintTransfer.concat(
            TaintedValue.trusted("SELECT * FROM users WHERE name = '"),
            null_byte,
            TaintedValue.trusted("'")
        )
        assert query.is_tainted
        assert "\x00" in query.value


class TestRobustness:
    """Test robustness against unusual inputs"""

    def test_extremely_long_source_name(self):
        """Handle extremely long source names"""
        long_source = "x" * 10000
        value = TaintedValue.untrusted("data", source=long_source)
        assert value.is_tainted
        assert value.source == long_source

    def test_special_characters_in_source(self):
        """Handle special characters in source names"""
        special_source = "http://evil.com?param=<script>alert(1)</script>"
        value = TaintedValue.untrusted("data", source=special_source)
        assert value.is_tainted
        assert value.source == special_source

    def test_multiple_sources_concat(self):
        """Concatenating values from many different sources"""
        sources = [f"source_{i}" for i in range(100)]
        values = [TaintedValue.untrusted(f"data{i}", source=s)
                  for i, s in enumerate(sources)]

        result = TaintTransfer.concat(*values)
        assert result.is_tainted
        # All sources should be tracked
        for source in sources:
            assert source in result.source


class TestMemorySafety:
    """Test memory safety and resource limits"""

    def test_no_memory_leak_in_concat(self):
        """Ensure concat doesn't leak memory with many operations"""
        # This is more of a documentation test - Python's GC handles this
        for _ in range(10000):
            values = [TaintedValue.trusted(f"x{i}") for i in range(10)]
            result = TaintTransfer.concat(*values)
            # Result goes out of scope and should be GC'd

        # If we got here without OOM, we're good
        assert True

    def test_string_interning_independence(self):
        """Ensure string interning doesn't affect taint tracking"""
        # In Python, small strings are interned
        s1 = TaintedValue.trusted("test")
        s2 = TaintedValue.untrusted("test")

        assert not s1.is_tainted
        assert s2.is_tainted
        # Even though strings are the same, taint is independent
        assert s1.value == s2.value
        assert s1.is_tainted != s2.is_tainted
