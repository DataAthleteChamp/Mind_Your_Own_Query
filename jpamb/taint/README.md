# JPAMB Taint Analysis Module

Variable-level taint tracking for SQL injection detection in Java programs.

## Overview

This module provides a variable-level taint analysis framework for detecting SQL injection vulnerabilities. Unlike character-level taint tracking (which uses bit-vectors per character), this implementation tracks taint at the variable level using boolean flags, providing a simpler yet effective approach for SQL injection detection.

## Architecture

The module consists of three main components:

### 1. TaintedValue (`value.py`)

Core abstraction for tracking tainted values.

**Key Features:**
- Tracks whether a value came from a trusted or untrusted source
- Stores the source of taint (e.g., "http_param", "file_io")
- Provides convenience methods for SQL safety checking

**Example:**
```python
from jpamb.taint import TaintedValue

# Create trusted value (from literal)
safe = TaintedValue.trusted("SELECT * FROM users WHERE id = ")

# Create untrusted value (from user input)
unsafe = TaintedValue.untrusted("1 OR 1=1", source="http_param")

# Check if safe for SQL
assert safe.is_safe_for_sql()  # True
assert not unsafe.is_safe_for_sql()  # False
```

### 2. TaintTransfer (`transfer.py`)

Transfer functions that define how taint propagates through string operations.

**Supported Operations:**
- `concat()` - String concatenation (tainted if ANY input is tainted)
- `substring()` - Substring extraction (preserves taint)
- `replace()` - String replacement (preserves taint)
- `trim()` - Whitespace trimming (preserves taint)
- `to_lower()` / `to_upper()` - Case conversion (preserves taint)
- `split()` - String splitting (all parts inherit taint)
- `join()` - String joining (tainted if delimiter OR any part is tainted)

**Example:**
```python
from jpamb.taint import TaintedValue, TaintTransfer

safe = TaintedValue.trusted("SELECT * FROM users WHERE id = ")
unsafe = TaintedValue.untrusted("1 OR 1=1")

# Concatenation propagates taint
query = TaintTransfer.concat(safe, unsafe)
assert query.is_tainted  # True - query is now tainted!

# Even SQL escaping doesn't sanitize
escaped = TaintTransfer.replace(unsafe, "'", "''")
assert escaped.is_tainted  # Still tainted!
```

### 3. SourceSinkDetector (`sources.py`)

Detects sources (where untrusted data originates) and sinks (where untrusted data becomes dangerous).

**Predefined Sources:**
- HTTP: `HttpServletRequest.getParameter`, `HttpServletRequest.getHeader`, etc.
- File I/O: `BufferedReader.readLine`, `FileReader.read`, etc.
- Network: `URLConnection.getInputStream`, `Socket.getInputStream`, etc.
- System: `System.getenv`, `System.getProperty`
- Console: `Scanner.nextLine`, `Console.readLine`

**Predefined Sinks (SQL Injection):**
- `Statement.execute`, `Statement.executeQuery`, `Statement.executeUpdate`
- `Connection.prepareStatement`, `Connection.prepareCall`
- Note: `PreparedStatement.setString()` is SAFE (parameterized)

**Example:**
```python
from jpamb.taint import SourceSinkDetector

detector = SourceSinkDetector.default()

# Check if method is a source
assert detector.is_source("javax.servlet.http.HttpServletRequest.getParameter")
assert detector.get_source_type("javax.servlet.http.HttpServletRequest.getParameter") == "http_request"

# Check if method is a sink
assert detector.is_sink("java.sql.Statement.execute")
assert detector.get_sink_type("java.sql.Statement.execute") == "sql_execution"
```

## Usage

### Basic Usage

```python
from jpamb.taint import TaintedValue, TaintTransfer, SourceSinkDetector

# Create values
query_base = TaintedValue.trusted("SELECT * FROM users WHERE id = ")
user_input = TaintedValue.untrusted("1 OR 1=1", source="http_param")

# Track taint through operations
query = TaintTransfer.concat(query_base, user_input)

# Check safety
if not query.is_safe_for_sql():
    print(f"⚠️ SQL Injection detected!")
    print(f"Tainted data from: {query.source}")
```

### Custom Sources and Sinks

```python
from jpamb.taint import SourceSinkDetector

# Define custom sources and sinks
custom_sources = {
    "com.myapp.api.Request.getParam",
    "com.myapp.cache.Cache.get"
}

custom_sinks = {
    "com.myapp.db.Database.executeRaw",
    "com.myapp.ldap.LDAP.query"
}

detector = SourceSinkDetector(custom_sources, custom_sinks)

# Now use detector to identify sources/sinks
if detector.is_source("com.myapp.api.Request.getParam"):
    # Mark as tainted
    pass
```

### Integration with JPAMB

```python
import jpamb
from jpamb.taint import TaintedValue, TaintTransfer, SourceSinkDetector

# Get method to analyze
methodid = jpamb.getmethodid(
    "taint_analyzer",
    "1.0",
    "Your Team Name",
    ["taint", "python", "sql"],
    for_science=True
)

# Initialize detector
detector = SourceSinkDetector.default()

# Perform taint analysis
# (See MASTER_PLAN.md for complete implementation)
```

## Design Decisions

### Variable-Level vs Character-Level Taint

This module implements **variable-level taint tracking** rather than character-level:

**Variable-Level (this implementation):**
```python
query = concat("SELECT ", user_input)
# → tainted=True (entire string is tainted)
```

**Character-Level (more complex):**
```python
query = concat("SELECT ", user_input)
# → [1,1,1,1,1,1,1,0,0,0,0,0] (per-character bit-vector)
```

**Why Variable-Level?**
1. **Simplicity**: 10% of complexity, 90% of the benefit
2. **Sufficient for SQL injection**: If ANY part of a query is tainted, it's vulnerable
3. **Performance**: O(1) memory per value vs O(string length)
4. **Implementation time**: 2 weeks vs 3-6 months for character-level

**When Character-Level Matters:**
- Partial sanitization (remove first N characters)
- String interleaving (safe-unsafe-safe patterns)
- Complex transformations

For SQL injection detection, variable-level is sufficient in 95%+ of cases.

### Conservative Taint Propagation

This implementation is **conservative** (over-approximating):
- If ANY input to an operation is tainted, the output is tainted
- Substring, replace, trim, case conversion all preserve taint
- Only operations with exclusively trusted inputs produce trusted outputs

This minimizes false negatives (missed vulnerabilities) at the cost of potential false positives.

## Testing

The module includes comprehensive test coverage:

```bash
# Run all taint tests
pytest test/test_taint*.py -v

# Run specific test class
pytest test/test_taint_transfer.py::TestConcatenation -v

# Run with coverage
pytest test/test_taint*.py --cov=jpamb.taint --cov-report=html
```

**Test Coverage:**
- 68 tests covering all major functionality
- Unit tests for each transfer function
- Integration tests for realistic SQL injection scenarios
- Edge case testing (empty strings, None values, etc.)

## Performance

Variable-level taint tracking is lightweight:
- **Memory**: O(1) per value (just a boolean flag + source string)
- **Time**: O(1) for taint propagation (no bit-vector operations)
- **Scalability**: Can analyze large programs efficiently

## Limitations

1. **No character-level precision**: Cannot track which specific characters are tainted
2. **No inter-procedural analysis**: Taint tracking limited to single method
3. **No path sensitivity**: Doesn't handle conditional sanitization
4. **Conservative**: May produce false positives for complex patterns

## Future Work

Potential improvements:
- Character-level taint tracking with bit-vectors
- Inter-procedural taint flow analysis
- Path-sensitive analysis
- Integration with symbolic execution
- Support for other injection types (XSS, command injection)
- Taint visualization tools

## References

### Academic Papers
- **Chin & Wagner (2009)** - "Efficient character-level taint tracking for Java"
- **Livshits & Lam (2005)** - "Finding security vulnerabilities in Java with static analysis"
- **Tripp et al. (2009)** - "TAJ: Effective taint analysis of web applications"

### Standards
- **OWASP Top 10** - SQL Injection (#3 in 2021)
- **CWE-89** - SQL Injection
- **SecuriBench Micro** - Academic security benchmark

## Contributing

When adding new features:
1. Follow PEP 8 style guidelines
2. Add type hints for all functions
3. Write comprehensive docstrings
4. Include unit tests (aim for >90% coverage)
5. Update this README with examples
6. Test with realistic SQL injection scenarios

## License

This code is part of the JPAMB project and follows the project's BSD-3-Clause license.

## Authors

DTU Compute Group 4:
- Jakub Lukaszewski (s253077)
- Jakub Piotrowski (s253074)
- Landon Hassin (s252773)
- Lawrence M. Ryan (s225243)
- Matthew Asano (s225134)

## See Also

- [MASTER_PLAN.md](../../MASTER_PLAN.md) - Complete project plan and timeline
- [project_proposal.md](../../project_proposal.md) - Original project proposal
- [JPAMB README](../../README.md) - Main JPAMB framework documentation
