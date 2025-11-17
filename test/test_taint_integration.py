"""
Integration tests for jpamb.taint module

Tests realistic SQL injection scenarios and complex taint flows.
"""

import pytest
from jpamb.taint import TaintedValue, TaintTransfer, SourceSinkDetector, concat


class TestRealisticSQLInjectionPatterns:
    """Test realistic SQL injection attack patterns"""

    def test_union_based_injection(self):
        """UNION-based SQL injection"""
        query_base = TaintedValue.trusted("SELECT * FROM users WHERE id = ")
        attack = TaintedValue.untrusted(
            "1 UNION SELECT username,password FROM admin--",
            source="http_param"
        )
        query = concat(query_base, attack)

        assert query.is_tainted
        assert not query.is_safe_for_sql()
        assert "http_param" in query.source

    def test_time_based_blind_injection(self):
        """Time-based blind SQL injection"""
        query_base = TaintedValue.trusted("SELECT * FROM products WHERE id = ")
        attack = TaintedValue.untrusted(
            "1 AND SLEEP(5)--",
            source="http_param"
        )
        query = concat(query_base, attack)

        assert query.is_tainted
        assert not query.is_safe_for_sql()

    def test_error_based_injection(self):
        """Error-based SQL injection"""
        query_base = TaintedValue.trusted("SELECT * FROM users WHERE name = '")
        attack = TaintedValue.untrusted(
            "admin' AND 1=CONVERT(int,(SELECT @@version))--",
            source="http_param"
        )
        query_end = TaintedValue.trusted("'")
        query = concat(query_base, attack, query_end)

        assert query.is_tainted

    def test_boolean_based_blind_injection(self):
        """Boolean-based blind SQL injection"""
        query_base = TaintedValue.trusted("SELECT * FROM users WHERE id = ")
        attack = TaintedValue.untrusted(
            "1 AND (SELECT COUNT(*) FROM admin) > 0--",
            source="http_param"
        )
        query = concat(query_base, attack)

        assert query.is_tainted


class TestSecondOrderInjection:
    """Test second-order SQL injection scenarios"""

    def test_stored_then_retrieved(self):
        """Data stored as tainted, then retrieved and used"""
        # First, tainted data is stored
        user_input = TaintedValue.untrusted("admin' OR '1'='1", source="http_param")

        # Simulate storage (taint persists)
        stored_data = user_input  # In real scenario, would be in database

        # Later, retrieved and used in query
        query_base = TaintedValue.trusted("SELECT * FROM users WHERE name = '")
        query_end = TaintedValue.trusted("'")
        query = concat(query_base, stored_data, query_end)

        assert query.is_tainted
        assert not query.is_safe_for_sql()


class TestComplexStringOperations:
    """Test complex string operation chains"""

    def test_multiple_transformations(self):
        """Chain of transformations preserves taint"""
        original = TaintedValue.untrusted("  ADMIN' OR '1'='1  ")

        # Chain of operations
        step1 = TaintTransfer.trim(original)
        step2 = TaintTransfer.to_lower(step1)
        step3 = TaintTransfer.replace(step2, "'", "''")
        step4 = TaintTransfer.substring(step3, 0, 20)

        assert step1.is_tainted
        assert step2.is_tainted
        assert step3.is_tainted
        assert step4.is_tainted
        assert not step4.is_safe_for_sql()

    def test_split_and_rejoin(self):
        """Split and rejoin operations"""
        tainted = TaintedValue.untrusted("admin,user,guest")

        # Split into parts
        parts = TaintTransfer.split(tainted, ",")

        # All parts should be tainted
        assert all(p.is_tainted for p in parts)

        # Rejoin with safe delimiter
        safe_delim = TaintedValue.trusted("|")
        rejoined = TaintTransfer.join(safe_delim, parts)

        assert rejoined.is_tainted  # Still tainted because parts are tainted

    def test_mixed_concat_chain(self):
        """Long chain of concatenations"""
        parts = [
            TaintedValue.trusted("SELECT "),
            TaintedValue.trusted("* "),
            TaintedValue.trusted("FROM "),
            TaintedValue.untrusted("users", source="http_param"),
            TaintedValue.trusted(" WHERE "),
            TaintedValue.trusted("id = "),
            TaintedValue.untrusted("1", source="http_param"),
        ]

        result = TaintTransfer.concat(*parts)

        assert result.is_tainted
        assert "http_param" in result.source


class TestDefensiveProgramming:
    """Test defensive programming patterns (still vulnerable)"""

    def test_input_validation_still_tainted(self):
        """Even "validated" user input is still tainted"""
        user_input = TaintedValue.untrusted("admin123")

        # Simulate validation (checking it's alphanumeric)
        # But it's still from untrusted source!
        validated = user_input  # Validation doesn't change taint

        query = concat(
            TaintedValue.trusted("SELECT * FROM users WHERE username = '"),
            validated,
            TaintedValue.trusted("'")
        )

        assert query.is_tainted
        assert not query.is_safe_for_sql()

    def test_length_check_still_tainted(self):
        """Checking length doesn't sanitize"""
        user_input = TaintedValue.untrusted("admin")

        # Even if we check length, still tainted
        if len(str(user_input.value)) <= 10:
            safe_length_input = user_input  # Length check doesn't sanitize

        query = concat(
            TaintedValue.trusted("SELECT * FROM users WHERE id = "),
            safe_length_input
        )

        assert query.is_tainted

    def test_whitelist_check_still_tainted(self):
        """Even whitelist checking doesn't make it safe in our model"""
        user_input = TaintedValue.untrusted("users", source="http_param")

        # Simulate whitelist check
        # In variable-level taint, even passing whitelist doesn't sanitize
        # (would need explicit sanitization marker)
        whitelisted = user_input

        query = concat(
            TaintedValue.trusted("SELECT * FROM "),
            whitelisted
        )

        assert query.is_tainted


class TestSourceSinkIntegration:
    """Test integration of source/sink detection with taint tracking"""

    def test_full_source_to_sink_flow(self):
        """Complete flow from source to sink"""
        detector = SourceSinkDetector.default()

        # Identify source
        source_method = "javax.servlet.http.HttpServletRequest.getParameter"
        assert detector.is_source(source_method)
        source_type = detector.get_source_type(source_method)

        # Create tainted value from source
        user_id = TaintedValue.untrusted("1 OR 1=1", source=source_type)

        # Build query
        query = concat(
            TaintedValue.trusted("SELECT * FROM users WHERE id = "),
            user_id
        )

        # Check sink
        sink_method = "java.sql.Statement.execute"
        assert detector.is_sink(sink_method)

        # Vulnerability: tainted data reaches sink
        assert query.is_tainted
        assert not query.is_safe_for_sql()

    def test_safe_parameterized_query_pattern(self):
        """Safe parameterized query uses only literals"""
        query = TaintedValue.trusted("SELECT * FROM users WHERE id = ?")

        # Parameter will be set safely via PreparedStatement.setString
        # which is NOT a sink (it's safe)

        assert not query.is_tainted
        assert query.is_safe_for_sql()


class TestEdgeCasesAndCornerCases:
    """Test edge cases and corner cases"""

    def test_empty_concat(self):
        """Concatenating empty tainted string"""
        empty_tainted = TaintedValue.untrusted("")
        safe = TaintedValue.trusted("SELECT *")

        result = concat(safe, empty_tainted)

        assert result.is_tainted  # Even empty tainted string taints result

    def test_null_value_handling(self):
        """Handling None/null values"""
        null_tainted = TaintedValue.untrusted(None)

        assert null_tainted.is_tainted
        assert null_tainted.value is None

    def test_numeric_value_in_concat(self):
        """Numeric values in concatenation"""
        num_tainted = TaintedValue.untrusted(42, source="http_param")
        query_base = TaintedValue.trusted("SELECT * FROM users WHERE id = ")

        result = concat(query_base, num_tainted)

        assert result.is_tainted
        assert "42" in result.value

    def test_special_characters(self):
        """Special SQL characters in tainted data"""
        special = TaintedValue.untrusted(
            "'; DROP TABLE users; --",
            source="http_param"
        )

        query = concat(
            TaintedValue.trusted("SELECT * FROM users WHERE name = '"),
            special,
            TaintedValue.trusted("'")
        )

        assert query.is_tainted
        assert "DROP TABLE" in query.value

    def test_unicode_characters(self):
        """Unicode characters in tainted data"""
        unicode_input = TaintedValue.untrusted("admin\u0027 OR \u00271\u0027=\u00271")

        query = concat(
            TaintedValue.trusted("SELECT * FROM users WHERE name = '"),
            unicode_input,
            TaintedValue.trusted("'")
        )

        assert query.is_tainted


class TestMultipleSourceTracking:
    """Test tracking multiple taint sources"""

    def test_multiple_sources_combined(self):
        """Combining data from multiple sources"""
        http_input = TaintedValue.untrusted("admin", source="http_param")
        file_input = TaintedValue.untrusted("secret", source="file_io")

        combined = concat(http_input, TaintedValue.trusted("_"), file_input)

        assert combined.is_tainted
        assert "http_param" in combined.source
        assert "file_io" in combined.source

    def test_source_tracking_through_operations(self):
        """Source information persists through operations"""
        original = TaintedValue.untrusted("attack", source="network")

        transformed = TaintTransfer.to_upper(original)
        trimmed = TaintTransfer.trim(transformed)

        assert trimmed.is_tainted
        assert trimmed.source == "network"


class TestPerformance:
    """Performance and scalability tests"""

    def test_large_concat(self):
        """Concatenating many values"""
        parts = []
        for i in range(100):
            if i % 2 == 0:
                parts.append(TaintedValue.trusted(f"part{i}"))
            else:
                parts.append(TaintedValue.untrusted(f"user{i}", source="http"))

        result = TaintTransfer.concat(*parts)

        assert result.is_tainted
        assert "http" in result.source

    def test_deep_operation_chain(self):
        """Deep chain of operations"""
        value = TaintedValue.untrusted("test")

        # Apply 50 operations
        for i in range(50):
            if i % 5 == 0:
                value = TaintTransfer.to_upper(value)
            elif i % 5 == 1:
                value = TaintTransfer.to_lower(value)
            elif i % 5 == 2:
                value = TaintTransfer.trim(value)
            elif i % 5 == 3:
                value = TaintTransfer.replace(value, "t", "T")
            else:
                value = concat(value, TaintedValue.trusted(" "))

        assert value.is_tainted


class TestDocumentedExamples:
    """Test all examples from documentation"""

    def test_readme_basic_example(self):
        """Example from README - Basic Usage"""
        query_base = TaintedValue.trusted("SELECT * FROM users WHERE id = ")
        user_input = TaintedValue.untrusted("1 OR 1=1", source="http_param")

        query = TaintTransfer.concat(query_base, user_input)

        assert not query.is_safe_for_sql()
        assert query.source == "http_param"

    def test_readme_escaping_example(self):
        """Example from README - SQL Escaping"""
        user_input = TaintedValue.untrusted("admin' OR '1'='1")
        escaped = TaintTransfer.replace(user_input, "'", "''")
        query_base = TaintedValue.trusted("SELECT * FROM users WHERE name = '")
        query_end = TaintedValue.trusted("'")
        query = concat(query_base, escaped, query_end)

        assert query.is_tainted
        assert not query.is_safe_for_sql()

    def test_readme_source_sink_example(self):
        """Example from README - Source/Sink Detection"""
        detector = SourceSinkDetector.default()

        assert detector.is_source("javax.servlet.http.HttpServletRequest.getParameter")
        assert detector.get_source_type(
            "javax.servlet.http.HttpServletRequest.getParameter"
        ) == "http_request"

        assert detector.is_sink("java.sql.Statement.execute")
        assert detector.get_sink_type("java.sql.Statement.execute") == "sql_execution"
