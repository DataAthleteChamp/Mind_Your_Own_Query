"""
Tests for jpamb.taint.value module
"""

import pytest
from jpamb.taint.value import TaintedValue, trusted, untrusted


class TestTaintedValueCreation:
    """Test creation of TaintedValue instances"""

    def test_trusted_creation(self):
        """Test creating trusted value"""
        val = TaintedValue.trusted("SELECT * FROM users")
        assert not val.is_tainted
        assert val.source == "literal"
        assert val.value == "SELECT * FROM users"

    def test_untrusted_creation(self):
        """Test creating untrusted value"""
        val = TaintedValue.untrusted("admin' OR '1'='1")
        assert val.is_tainted
        assert val.source == "user_input"
        assert val.value == "admin' OR '1'='1"

    def test_trusted_with_custom_source(self):
        """Test trusted value with custom source"""
        val = TaintedValue.trusted("config_value", source="config_file")
        assert not val.is_tainted
        assert val.source == "config_file"

    def test_untrusted_with_custom_source(self):
        """Test untrusted value with custom source"""
        val = TaintedValue.untrusted("user@example.com", source="http_header")
        assert val.is_tainted
        assert val.source == "http_header"

    def test_convenience_functions(self):
        """Test convenience functions trusted() and untrusted()"""
        safe = trusted("safe")
        assert not safe.is_tainted

        unsafe = untrusted("unsafe")
        assert unsafe.is_tainted


class TestTaintedValueMethods:
    """Test TaintedValue methods"""

    def test_is_safe_for_sql_trusted(self):
        """Test is_safe_for_sql() for trusted value"""
        val = TaintedValue.trusted("SELECT *")
        assert val.is_safe_for_sql()

    def test_is_safe_for_sql_untrusted(self):
        """Test is_safe_for_sql() for untrusted value"""
        val = TaintedValue.untrusted("'; DROP TABLE users--")
        assert not val.is_safe_for_sql()

    def test_get_string_value(self):
        """Test get_string_value() method"""
        val = TaintedValue.trusted("test")
        assert val.get_string_value() == "test"

    def test_get_string_value_with_int(self):
        """Test get_string_value() with non-string value"""
        val = TaintedValue.trusted(42)
        assert val.get_string_value() == "42"

    def test_repr(self):
        """Test __repr__ method"""
        trusted_val = TaintedValue.trusted("safe")
        untrusted_val = TaintedValue.untrusted("unsafe")

        assert "✓" in repr(trusted_val)
        assert "⚠️" in repr(untrusted_val)
        assert "'safe'" in repr(trusted_val)
        assert "'unsafe'" in repr(untrusted_val)

    def test_str(self):
        """Test __str__ method"""
        trusted_val = TaintedValue.trusted("safe")
        untrusted_val = TaintedValue.untrusted("unsafe")

        assert "TRUSTED" in str(trusted_val)
        assert "TAINTED" in str(untrusted_val)


class TestTaintedValueEdgeCases:
    """Test edge cases"""

    def test_empty_string_trusted(self):
        """Test trusted empty string"""
        val = TaintedValue.trusted("")
        assert not val.is_tainted
        assert val.value == ""

    def test_empty_string_untrusted(self):
        """Test untrusted empty string"""
        val = TaintedValue.untrusted("")
        assert val.is_tainted
        assert val.value == ""

    def test_none_value(self):
        """Test None value"""
        val = TaintedValue.trusted(None)
        assert val.value is None
        assert not val.is_tainted

    def test_numeric_value(self):
        """Test numeric value"""
        val = TaintedValue.untrusted(42)
        assert val.value == 42
        assert val.is_tainted