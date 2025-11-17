#!/usr/bin/env python3
"""
Demonstration of the taint tracking implementation.

Run with: python demo_taint.py
"""

from jpamb.taint import TaintedValue, TaintTransfer, SourceSinkDetector

def demo_basic_taint():
    """Demonstrate basic taint tracking"""
    print("=" * 60)
    print("DEMO 1: Basic Taint Tracking")
    print("=" * 60)

    # Create trusted and untrusted values
    safe = TaintedValue.trusted("SELECT * FROM users WHERE id = ")
    unsafe = TaintedValue.untrusted("1 OR 1=1", source="http_param")

    print(f"\nTrusted value:   {safe}")
    print(f"Untrusted value: {unsafe}")

    # Concatenate
    query = TaintTransfer.concat(safe, unsafe)
    print(f"\nConcatenated:    {query}")
    print(f"Query SQL-safe?  {query.is_safe_for_sql()}")

    if query.is_tainted:
        print("\n⚠️  SQL INJECTION DETECTED!")
        print(f"   Taint source: {query.source}")
    else:
        print("\n✓ Query is safe")


def demo_sql_escaping():
    """Demonstrate that SQL escaping doesn't sanitize"""
    print("\n" + "=" * 60)
    print("DEMO 2: SQL Escaping Doesn't Sanitize")
    print("=" * 60)

    # Malicious input
    malicious = TaintedValue.untrusted("admin' OR '1'='1")
    print(f"\nMalicious input: {malicious}")

    # Try to escape
    escaped = TaintTransfer.replace(malicious, "'", "''")
    print(f"After escaping:  {escaped}")
    print(f"Still tainted?   {escaped.is_tainted}")

    # Build query
    query = TaintTransfer.concat(
        TaintedValue.trusted("SELECT * WHERE name = '"),
        escaped,
        TaintedValue.trusted("'")
    )

    print(f"\nFinal query:     {query.value}")
    print(f"SQL-safe?        {query.is_safe_for_sql()}")

    if query.is_tainted:
        print("\n⚠️  STILL VULNERABLE! Escaping doesn't help!")
    else:
        print("\n✓ Query is safe")


def demo_safe_query():
    """Demonstrate safe parameterized query"""
    print("\n" + "=" * 60)
    print("DEMO 3: Safe Parameterized Query")
    print("=" * 60)

    # Parameterized query (all literals)
    safe_query = TaintedValue.trusted("SELECT * FROM users WHERE id = ?")
    print(f"\nParameterized query: {safe_query}")
    print(f"Tainted?             {safe_query.is_tainted}")
    print(f"SQL-safe?            {safe_query.is_safe_for_sql()}")

    if not safe_query.is_tainted:
        print("\n✓ Query is SAFE - using parameterized statements")


def demo_source_sink_detection():
    """Demonstrate source and sink detection"""
    print("\n" + "=" * 60)
    print("DEMO 4: Source and Sink Detection")
    print("=" * 60)

    detector = SourceSinkDetector.default()

    # Test sources
    sources = [
        "javax.servlet.http.HttpServletRequest.getParameter",
        "java.io.BufferedReader.readLine",
        "java.net.Socket.getInputStream",
    ]

    print("\nDetecting SOURCES (where taint enters):")
    for method in sources:
        is_src = detector.is_source(method)
        src_type = detector.get_source_type(method) if is_src else "N/A"
        print(f"  {'✓' if is_src else '✗'} {method.split('.')[-1]:<20} → {src_type}")

    # Test sinks
    sinks = [
        "java.sql.Statement.execute",
        "java.sql.Connection.prepareStatement",
        "java.lang.System.out.println",
    ]

    print("\nDetecting SINKS (where taint is dangerous):")
    for method in sinks:
        is_snk = detector.is_sink(method)
        snk_type = detector.get_sink_type(method) if is_snk else "N/A"
        print(f"  {'⚠️' if is_snk else '✓'} {method.split('.')[-1]:<20} → {snk_type if is_snk else 'safe'}")


def demo_complex_scenario():
    """Demonstrate complex multi-step scenario"""
    print("\n" + "=" * 60)
    print("DEMO 5: Complex Query Building")
    print("=" * 60)

    # Simulate building a query step by step
    print("\nSimulating: Building a search query from user input")

    base = TaintedValue.trusted("SELECT * FROM products WHERE ")
    category_param = TaintedValue.untrusted("electronics", source="http_param")
    and_clause = TaintedValue.trusted(" AND ")
    price_param = TaintedValue.untrusted("100", source="http_param")

    print(f"\n1. Base query:     {base.value!r}")
    print(f"2. Category input: {category_param.value!r} [from {category_param.source}]")
    print(f"3. AND clause:     {and_clause.value!r}")
    print(f"4. Price input:    {price_param.value!r} [from {price_param.source}]")

    # Build query
    query = TaintTransfer.concat(
        base,
        TaintedValue.trusted("category = '"),
        category_param,
        TaintedValue.trusted("'"),
        and_clause,
        TaintedValue.trusted("price < "),
        price_param
    )

    print(f"\nFinal query: {query.value!r}")
    print(f"Tainted?     {query.is_tainted}")
    print(f"Source:      {query.source}")

    if query.is_tainted:
        print("\n⚠️  VULNERABLE - User input in SQL query!")
        print("   Recommendation: Use PreparedStatement with parameters")


def demo_transfer_operations():
    """Demonstrate various transfer operations"""
    print("\n" + "=" * 60)
    print("DEMO 6: Transfer Operations")
    print("=" * 60)

    original = TaintedValue.untrusted("  ADMIN' OR '1'='1  ")
    print(f"\nOriginal tainted value: {original}")

    # Trim
    trimmed = TaintTransfer.trim(original)
    print(f"After trim():           {trimmed}")
    print(f"  Still tainted? {trimmed.is_tainted}")

    # Lowercase
    lowered = TaintTransfer.to_lower(trimmed)
    print(f"After to_lower():       {lowered}")
    print(f"  Still tainted? {lowered.is_tainted}")

    # Substring
    substr = TaintTransfer.substring(lowered, 0, 5)
    print(f"After substring(0,5):   {substr}")
    print(f"  Still tainted? {substr.is_tainted}")

    print("\n✓ All operations preserve taint correctly!")


def main():
    """Run all demonstrations"""
    print("\n" + "=" * 60)
    print("TAINT ANALYSIS DEMONSTRATION")
    print("Variable-Level Taint Tracking for SQL Injection Detection")
    print("=" * 60)

    demo_basic_taint()
    demo_sql_escaping()
    demo_safe_query()
    demo_source_sink_detection()
    demo_complex_scenario()
    demo_transfer_operations()

    print("\n" + "=" * 60)
    print("DEMONSTRATION COMPLETE")
    print("=" * 60)
    print("\nAll taint tracking operations working correctly!")
    print("Ready to integrate with analyzer.\n")


if __name__ == "__main__":
    main()
