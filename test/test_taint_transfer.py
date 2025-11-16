"""
Tests for jpamb.taint.transfer module
"""

import pytest
from jpamb.taint.value import TaintedValue
from jpamb.taint.transfer import TaintTransfer, concat


class TestConcatenation:
    """Test concatenation transfer function"""

    def test_concat_two_trusted(self):
        """Concatenating two trusted values produces trusted result"""
        s1 = TaintedValue.trusted("SELECT ")
        s2 = TaintedValue.trusted("* FROM users")
        result = TaintTransfer.concat(s1, s2)

        assert not result.is_tainted
        assert result.value == "SELECT * FROM users"
        assert result.source == "literal"

    def test_concat_trusted_and_untrusted(self):
        """Concatenating trusted + untrusted produces untrusted result"""
        s1 = TaintedValue.trusted("SELECT * FROM users WHERE id = ")
        s2 = TaintedValue.untrusted("1 OR 1=1")
        result = TaintTransfer.concat(s1, s2)

        assert result.is_tainted
        assert result.value == "SELECT * FROM users WHERE id = 1 OR 1=1"
        assert "user_input" in result.source

    def test_concat_untrusted_and_trusted(self):
        """Concatenating untrusted + trusted produces untrusted result"""
        s1 = TaintedValue.untrusted("admin")
        s2 = TaintedValue.trusted("@example.com")
        result = TaintTransfer.concat(s1, s2)

        assert result.is_tainted
        assert result.value == "admin@example.com"

    def test_concat_two_untrusted(self):
        """Concatenating two untrusted values produces untrusted result"""
        s1 = TaintedValue.untrusted("admin", source="http_param")
        s2 = TaintedValue.untrusted("password", source="http_param")
        result = TaintTransfer.concat(s1, s2)

        assert result.is_tainted
        assert result.value == "adminpassword"
        assert "http_param" in result.source

    def test_concat_multiple_values(self):
        """Concatenating multiple values"""
        s1 = TaintedValue.trusted("SELECT * FROM users WHERE ")
        s2 = TaintedValue.trusted("name = '")
        s3 = TaintedValue.untrusted("admin")
        s4 = TaintedValue.trusted("'")
        result = TaintTransfer.concat(s1, s2, s3, s4)

        assert result.is_tainted
        assert result.value == "SELECT * FROM users WHERE name = 'admin'"

    def test_concat_convenience_function(self):
        """Test concat() convenience function"""
        result = concat(
            TaintedValue.trusted("Hello "),
            TaintedValue.untrusted("world")
        )
        assert result.is_tainted


class TestSubstring:
    """Test substring transfer function"""

    def test_substring_preserves_taint(self):
        """Taking substring of tainted string keeps it tainted"""
        tainted = TaintedValue.untrusted("admin' OR '1'='1")
        result = TaintTransfer.substring(tainted, 0, 5)

        assert result.is_tainted
        assert result.value == "admin"
        assert result.source == tainted.source

    def test_substring_trusted_remains_trusted(self):
        """Taking substring of trusted string keeps it trusted"""
        trusted = TaintedValue.trusted("SELECT * FROM users")
        result = TaintTransfer.substring(trusted, 0, 6)

        assert not result.is_tainted
        assert result.value == "SELECT"

    def test_substring_with_only_start(self):
        """Substring with only start index (to end)"""
        val = TaintedValue.untrusted("test string")
        result = TaintTransfer.substring(val, 5)

        assert result.value == "string"
        assert result.is_tainted

    def test_substring_empty_result(self):
        """Substring that results in empty string"""
        val = TaintedValue.untrusted("test")
        result = TaintTransfer.substring(val, 0, 0)

        assert result.value == ""
        assert result.is_tainted  # Empty but still tainted!


class TestReplace:
    """Test replace transfer function"""

    def test_replace_preserves_taint(self):
        """Replacing in tainted string keeps it tainted"""
        tainted = TaintedValue.untrusted("admin'")
        result = TaintTransfer.replace(tainted, "'", "''")

        assert result.is_tainted
        assert result.value == "admin''"

    def test_replace_sql_escaping_still_tainted(self):
        """SQL escaping doesn't sanitize tainted data"""
        malicious = TaintedValue.untrusted("admin' OR '1'='1")
        escaped = TaintTransfer.replace(malicious, "'", "''")

        assert escaped.is_tainted  # Still tainted!
        assert escaped.value == "admin'' OR ''1''=''1"

    def test_replace_trusted_remains_trusted(self):
        """Replacing in trusted string keeps it trusted"""
        trusted = TaintedValue.trusted("Hello world")
        result = TaintTransfer.replace(trusted, "world", "there")

        assert not result.is_tainted
        assert result.value == "Hello there"

    def test_replace_no_match(self):
        """Replace with no matches"""
        val = TaintedValue.untrusted("test")
        result = TaintTransfer.replace(val, "xyz", "abc")

        assert result.value == "test"
        assert result.is_tainted


class TestTrim:
    """Test trim transfer function"""

    def test_trim_preserves_taint(self):
        """Trimming tainted string keeps it tainted"""
        tainted = TaintedValue.untrusted("  malicious  ")
        result = TaintTransfer.trim(tainted)

        assert result.is_tainted
        assert result.value == "malicious"

    def test_trim_trusted_remains_trusted(self):
        """Trimming trusted string keeps it trusted"""
        trusted = TaintedValue.trusted("  SELECT  ")
        result = TaintTransfer.trim(trusted)

        assert not result.is_tainted
        assert result.value == "SELECT"

    def test_trim_no_whitespace(self):
        """Trim with no whitespace"""
        val = TaintedValue.untrusted("nowhitespace")
        result = TaintTransfer.trim(val)

        assert result.value == "nowhitespace"
        assert result.is_tainted


class TestCaseConversion:
    """Test case conversion transfer functions"""

    def test_to_lower_preserves_taint(self):
        """Converting to lowercase preserves taint"""
        tainted = TaintedValue.untrusted("ADMIN")
        result = TaintTransfer.to_lower(tainted)

        assert result.is_tainted
        assert result.value == "admin"

    def test_to_upper_preserves_taint(self):
        """Converting to uppercase preserves taint"""
        tainted = TaintedValue.untrusted("admin")
        result = TaintTransfer.to_upper(tainted)

        assert result.is_tainted
        assert result.value == "ADMIN"

    def test_to_lower_trusted_remains_trusted(self):
        """Converting trusted string to lowercase keeps it trusted"""
        trusted = TaintedValue.trusted("SELECT")
        result = TaintTransfer.to_lower(trusted)

        assert not result.is_tainted
        assert result.value == "select"

    def test_to_upper_trusted_remains_trusted(self):
        """Converting trusted string to uppercase keeps it trusted"""
        trusted = TaintedValue.trusted("select")
        result = TaintTransfer.to_upper(trusted)

        assert not result.is_tainted
        assert result.value == "SELECT"


class TestSplit:
    """Test split transfer function"""

    def test_split_preserves_taint_in_all_parts(self):
        """Splitting tainted string taints all parts"""
        tainted = TaintedValue.untrusted("admin,user,guest")
        parts = TaintTransfer.split(tainted, ",")

        assert len(parts) == 3
        assert all(p.is_tainted for p in parts)
        assert [p.value for p in parts] == ["admin", "user", "guest"]

    def test_split_trusted_remains_trusted(self):
        """Splitting trusted string keeps all parts trusted"""
        trusted = TaintedValue.trusted("one,two,three")
        parts = TaintTransfer.split(trusted, ",")

        assert len(parts) == 3
        assert all(not p.is_tainted for p in parts)

    def test_split_single_part(self):
        """Split with no delimiter found"""
        val = TaintedValue.untrusted("nodlimiter")
        parts = TaintTransfer.split(val, ",")

        assert len(parts) == 1
        assert parts[0].value == "nodlimiter"
        assert parts[0].is_tainted


class TestJoin:
    """Test join transfer function"""

    def test_join_with_tainted_delimiter(self):
        """Joining with tainted delimiter taints result"""
        tainted_delim = TaintedValue.untrusted(",")
        parts = [
            TaintedValue.trusted("one"),
            TaintedValue.trusted("two")
        ]
        result = TaintTransfer.join(tainted_delim, parts)

        assert result.is_tainted
        assert result.value == "one,two"

    def test_join_with_tainted_part(self):
        """Joining with any tainted part taints result"""
        safe_delim = TaintedValue.trusted(",")
        parts = [
            TaintedValue.trusted("safe"),
            TaintedValue.untrusted("unsafe")
        ]
        result = TaintTransfer.join(safe_delim, parts)

        assert result.is_tainted
        assert result.value == "safe,unsafe"

    def test_join_all_trusted(self):
        """Joining all trusted values produces trusted result"""
        safe_delim = TaintedValue.trusted(",")
        parts = [
            TaintedValue.trusted("one"),
            TaintedValue.trusted("two"),
            TaintedValue.trusted("three")
        ]
        result = TaintTransfer.join(safe_delim, parts)

        assert not result.is_tainted
        assert result.value == "one,two,three"


class TestSQLInjectionScenarios:
    """Test realistic SQL injection scenarios"""

    def test_basic_sql_injection(self):
        """Basic SQL injection pattern"""
        query_base = TaintedValue.trusted("SELECT * FROM users WHERE id = ")
        user_input = TaintedValue.untrusted("1 OR 1=1", source="http_param")
        query = concat(query_base, user_input)

        assert query.is_tainted
        assert not query.is_safe_for_sql()
        assert "http_param" in query.source

    def test_safe_parameterized_query(self):
        """Safe parameterized query (all literals)"""
        query = TaintedValue.trusted("SELECT * FROM users WHERE id = ?")

        assert not query.is_tainted
        assert query.is_safe_for_sql()

    def test_escaped_but_still_unsafe(self):
        """SQL escaping doesn't make tainted data safe"""
        user_input = TaintedValue.untrusted("admin' OR '1'='1")
        escaped = TaintTransfer.replace(user_input, "'", "''")
        query_base = TaintedValue.trusted("SELECT * FROM users WHERE name = '")
        query_end = TaintedValue.trusted("'")
        query = concat(query_base, escaped, query_end)

        assert query.is_tainted  # Still unsafe!
        assert not query.is_safe_for_sql()

    def test_complex_query_building(self):
        """Complex query with multiple concatenations"""
        base = TaintedValue.trusted("SELECT * FROM ")
        table = TaintedValue.untrusted("users", source="http_param")
        where = TaintedValue.trusted(" WHERE id = ")
        value = TaintedValue.untrusted("1", source="http_param")

        query = concat(base, table, where, value)

        assert query.is_tainted
        assert not query.is_safe_for_sql()