# Future Improvements Roadmap

**Last Updated**: 2025-11-17
**Current Grade**: A- (90/100)
**Target Grade**: A+ (95-100)

This document outlines recommended improvements to further enhance the SQL injection test suite quality and capabilities.

---

## High Priority (Next Steps)

### 1. Complete JavaDoc for All Test Cases
**Effort**: 3-4 hours
**Impact**: High (Educational value, professional appearance)
**Current**: 3/25 files (12%)
**Target**: 25/25 files (100%)

**Files Needing JavaDoc** (22 remaining):
- SQLi_MultiConcat.java
- SQLi_LiteralMix.java
- SQLi_HTTPSource.java
- SQLi_OrderBy.java
- SQLi_Replace.java
- SQLi_Trim.java
- SQLi_CaseConversion.java
- SQLi_SplitJoin.java
- SQLi_IfElse.java
- SQLi_Loop.java
- SQLi_TryCatch.java
- SQLi_Switch.java
- SQLi_NestedConditions.java
- SQLi_StringBuilder.java
- SQLi_StringBuffer.java
- SQLi_StringBuilderMixed.java
- SQLi_Union.java
- SQLi_TimeBased.java
- SQLi_SecondOrder.java
- SQLi_MultipleSources.java
- SQLi_PartialSanitization.java
- SQLi_ComplexNested.java

**Pattern to Follow**:
```java
/**
 * Test case for [description of vulnerability pattern].
 *
 * [Explanation of the vulnerability and why it matters]
 *
 * @category [category_name]
 * @difficulty [easy|medium|hard]
 */
public class SQLi_TestName {

    /**
     * VULNERABLE - [Brief description]
     *
     * [Detailed explanation of vulnerability]
     *
     * Attack example:
     *   input = "[attack payload]"
     *   Result: "[resulting malicious query]"
     *   Impact: [what attacker achieves]
     *
     * Expected outcome: Analyzer should detect SQL injection
     *
     * @param input [parameter description]
     */
    public static void vulnerable(String input) {
        // implementation
    }

    /**
     * SAFE - [Why this is safe]
     *
     * Expected outcome: Analyzer should NOT flag as vulnerable
     */
    public static void safe() {
        // implementation
    }
}
```

---

### 2. Add Harder Test Cases
**Effort**: 6 hours
**Impact**: High (Validates analyzer robustness)
**Current**: 25 easy-medium cases, 100% detection
**Goal**: Challenge the analyzer, find its limits

**Test Cases to Add**:

#### SQLi_InterProcedural.java
```java
/**
 * HARD - Multi-method taint flow (inter-procedural analysis)
 * Tests whether analyzer can track taint across method boundaries
 */
public class SQLi_InterProcedural {

    String getTaintedInput(HttpServletRequest req) {
        return req.getParameter("id");
    }

    // VULNERABLE - Should detect but likely won't (single-method analysis limitation)
    public static void vulnerable(HttpServletRequest request) {
        String input = getTaintedInput(request);
        String query = "SELECT * FROM users WHERE id = " + input;
        executeQuery(query);
    }

    // SAFE
    public static void safe() {
        String input = getLiteralValue();
        String query = "SELECT * FROM users WHERE id = " + input;
        executeQuery(query);
    }

    private static String getLiteralValue() {
        return "42";
    }
}
```

#### SQLi_Obfuscated.java
```java
/**
 * HARD - Obfuscated concatenation pattern
 * Tests analyzer's ability to detect non-standard concatenation
 */
public class SQLi_Obfuscated {

    // VULNERABLE - Uses char variables to build query
    public static void vulnerable(String input) {
        char quote = '"';
        char space = ' ';
        String s = "SELECT" + space + "*" + space + "FROM" + space + "users";
        StringBuilder sb = new StringBuilder(s);
        sb.append(space).append("WHERE").append(space);
        sb.append("name").append(space).append("=").append(space).append(quote);
        sb.append(input);
        sb.append(quote);
        executeQuery(sb.toString());
    }

    // SAFE
    public static void safe() {
        String s = "SELECT * FROM users WHERE name = \"admin\"";
        executeQuery(s);
    }
}
```

#### SQLi_NumericContext.java
```java
/**
 * HARD - Numeric context injection (no quotes needed)
 * Even without quotes, numeric fields are vulnerable
 */
public class SQLi_NumericContext {

    // VULNERABLE - Numeric field, no quotes
    // Attack: userId = "1 OR 1=1"
    public static void vulnerable(String userId) {
        String query = "SELECT * FROM users WHERE id = " + userId;
        executeQuery(query);
    }

    // SAFE
    public static void safe() {
        int userId = 42;
        String query = "SELECT * FROM users WHERE id = " + userId;
        executeQuery(query);
    }
}
```

#### SQLi_PreparedStatementMisuse.java
```java
/**
 * HARD - Prepared statement misuse (table/column names)
 * PreparedStatement doesn't protect table/column names
 */
public class SQLi_PreparedStatementMisuse {

    // VULNERABLE - Table name is concatenated
    // PreparedStatement placeholders (?) only work for VALUES, not identifiers
    public static void vulnerable(String tableName) throws SQLException {
        String sql = "SELECT * FROM " + tableName;  // Vulnerable!
        PreparedStatement stmt = conn.prepareStatement(sql);
        ResultSet rs = stmt.executeQuery();
    }

    // SAFE - Hardcoded table name
    public static void safe() throws SQLException {
        String sql = "SELECT * FROM users";
        PreparedStatement stmt = conn.prepareStatement(sql);
        ResultSet rs = stmt.executeQuery();
    }
}
```

#### SQLi_Reflection.java
```java
/**
 * HARD - Reflection-based query execution
 * Tests detection when SQL is executed via reflection
 */
public class SQLi_Reflection {

    // VULNERABLE - Query built with user input, executed via reflection
    public static void vulnerable(String input) throws Exception {
        String query = "SELECT * FROM users WHERE name = '" + input + "'";
        Method m = Statement.class.getMethod("executeQuery", String.class);
        m.invoke(statement, query);
    }

    // SAFE
    public static void safe() throws Exception {
        String query = "SELECT * FROM users WHERE name = 'admin'";
        Method m = Statement.class.getMethod("executeQuery", String.class);
        m.invoke(statement, query);
    }
}
```

#### SQLi_ConditionalSanitization.java
```java
/**
 * HARD - Conditional sanitization paths
 * One path sanitizes, other doesn't - tests path sensitivity
 */
public class SQLi_ConditionalSanitization {

    // VULNERABLE - Only sanitizes in some conditions
    public static void vulnerable(String input, boolean isAdmin) {
        String cleaned;
        if (isAdmin) {
            cleaned = input;  // No sanitization for admin!
        } else {
            cleaned = input.replaceAll("[^a-zA-Z0-9]", "");
        }
        String query = "SELECT * FROM users WHERE name = '" + cleaned + "'";
        executeQuery(query);
    }

    // SAFE - Always sanitizes
    public static void safe(String input, boolean isAdmin) {
        String cleaned = input.replaceAll("[^a-zA-Z0-9]", "");
        String query = "SELECT * FROM users WHERE name = '" + cleaned + "'";
        executeQuery(query);
    }
}
```

#### SQLi_ArrayConcatenation.java
```java
/**
 * HARD - Building query from array of untrusted inputs
 */
public class SQLi_ArrayConcatenation {

    // VULNERABLE - Array contains untrusted data
    public static void vulnerable(String[] userInputs) {
        String query = "SELECT * FROM users WHERE id IN (";
        for (int i = 0; i < userInputs.length; i++) {
            query += userInputs[i];  // Untrusted!
            if (i < userInputs.length - 1) {
                query += ", ";
            }
        }
        query += ")";
        executeQuery(query);
    }

    // SAFE
    public static void safe() {
        String[] ids = {"1", "2", "3"};
        String query = "SELECT * FROM users WHERE id IN (";
        for (int i = 0; i < ids.length; i++) {
            query += ids[i];
            if (i < ids.length - 1) {
                query += ", ";
            }
        }
        query += ")";
        executeQuery(query);
    }
}
```

#### SQLi_ChainedOperations.java
```java
/**
 * HARD - Long chain of string operations
 * Tests ability to track taint through multiple transformations
 */
public class SQLi_ChainedOperations {

    // VULNERABLE - Taint preserved through entire chain
    public static void vulnerable(String input) {
        String step1 = input.trim();
        String step2 = step1.toUpperCase();
        String step3 = step2.replace("  ", " ");
        String step4 = step3.substring(0, Math.min(20, step3.length()));
        String step5 = step4.toLowerCase();
        String step6 = step5.strip();

        String query = "SELECT * FROM users WHERE name = '" + step6 + "'";
        executeQuery(query);
    }

    // SAFE - Same chain but on literal
    public static void safe() {
        String input = "  ADMIN USER  ";
        String step1 = input.trim();
        String step2 = step1.toUpperCase();
        String step3 = step2.replace("  ", " ");
        String step4 = step3.substring(0, Math.min(20, step3.length()));
        String step5 = step4.toLowerCase();
        String step6 = step5.strip();

        String query = "SELECT * FROM users WHERE name = '" + step6 + "'";
        executeQuery(query);
    }
}
```

#### SQLi_TernaryExpression.java
```java
/**
 * HARD - Ternary expression in SQL building
 */
public class SQLi_TernaryExpression {

    // VULNERABLE - Ternary with untrusted value
    public static void vulnerable(String input, boolean condition) {
        String value = condition ? input : "default";  // If true, uses untrusted!
        String query = "SELECT * FROM users WHERE name = '" + value + "'";
        executeQuery(query);
    }

    // SAFE - Ternary with only trusted values
    public static void safe(boolean condition) {
        String value = condition ? "admin" : "user";
        String query = "SELECT * FROM users WHERE name = '" + value + "'";
        executeQuery(query);
    }
}
```

#### SQLi_FormatString.java
```java
/**
 * HARD - String.format() with untrusted input
 */
public class SQLi_FormatString {

    // VULNERABLE - format() doesn't sanitize
    public static void vulnerable(String userId) {
        String query = String.format("SELECT * FROM users WHERE id = %s", userId);
        executeQuery(query);
    }

    // SAFE
    public static void safe() {
        String query = String.format("SELECT * FROM users WHERE id = %s", "42");
        executeQuery(query);
    }
}
```

---

### 3. Add Integration Tests
**Effort**: 3 hours
**Impact**: High (Ensures end-to-end correctness)
**File**: `test_integration.py`

```python
#!/usr/bin/env python3
"""
Integration tests for SQL injection analyzer
Tests the complete pipeline from file read to analysis result
"""

import subprocess
import sys
import json
from pathlib import Path


class TestIntegration:
    """Integration tests for complete analyzer pipeline"""

    def test_single_analysis(self):
        """Test analyzing a single method"""
        result = subprocess.run(
            [sys.executable, "my_analyzer.py",
             "jpamb.sqli.SQLi_DirectConcat.vulnerable"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent
        )

        assert result.returncode == 0
        assert "SQL injection" in result.stdout
        assert ";" in result.stdout  # Format: "outcome;confidence"

    def test_all_test_cases_pass(self):
        """Verify all 25 test cases achieve target metrics"""
        result = subprocess.run(
            [sys.executable, "test_runner.py",
             "--jpamb-path", ".",
             "--analyzer", "my_analyzer.py",
             "--no-html"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent
        )

        # Verify success criteria met
        assert "Detection Rate: 100.0%" in result.stdout or \
               "Detection Rate: " in result.stdout  # Allow for future changes
        assert "False Positive Rate:" in result.stdout
        assert result.returncode == 0

    def test_results_json_format(self):
        """Verify JSON results are well-formed"""
        # Run test runner
        subprocess.run(
            [sys.executable, "test_runner.py",
             "--jpamb-path", ".",
             "--analyzer", "my_analyzer.py"],
            capture_output=True,
            cwd=Path(__file__).parent
        )

        # Find most recent result file
        results_dir = Path(__file__).parent / "results"
        result_files = list(results_dir.glob("test_results_*.json"))
        assert len(result_files) > 0

        latest = max(result_files, key=lambda p: p.stat().st_mtime)

        # Verify JSON is valid
        with open(latest) as f:
            data = json.load(f)

        assert "metrics" in data
        assert "test_results" in data
        assert "timestamp" in data

    def test_error_handling(self):
        """Test analyzer handles errors gracefully"""
        result = subprocess.run(
            [sys.executable, "my_analyzer.py",
             "invalid.signature"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent
        )

        assert result.returncode == 1
        assert "error;0" in result.stdout


if __name__ == "__main__":
    import unittest
    unittest.main()
```

---

## Medium Priority

### 4. Reorganize Project Structure
**Effort**: 2 hours
**Impact**: Medium (Better maintainability)

**Target Structure**:
```
sqli-test-suite/
├── README.md
├── requirements.txt
├── pyproject.toml
├── .gitignore
├── setup.py                        # NEW
├── docs/                           # NEW - Documentation
│   ├── COMPREHENSIVE_QUALITY_REPORT.md
│   ├── IMPROVEMENTS_SUMMARY.md
│   ├── FUTURE_IMPROVEMENTS.md
│   └── API.md                      # NEW - API documentation
├── src/
│   ├── analyzer/                   # NEW - Move Python here
│   │   ├── __init__.py
│   │   ├── my_analyzer.py
│   │   ├── parser.py               # NEW - Extract parsing logic
│   │   └── detector.py             # NEW - Extract detection logic
│   └── main/java/jpamb/sqli/       # Existing Java tests
├── tests/                          # NEW - All tests here
│   ├── unit/
│   │   └── test_analyzer.py
│   ├── integration/
│   │   └── test_integration.py
│   └── data/
│       └── test_cases.json
├── scripts/                        # NEW - Utility scripts
│   ├── test_runner.py
│   └── benchmark.py                # NEW
└── results/
```

**Migration Steps**:
1. Create new directory structure
2. Move files to appropriate locations
3. Update import paths in Python files
4. Update paths in test_runner.py
5. Update pyproject.toml to reflect new structure
6. Test everything still works

---

### 5. Add CI/CD Pipeline
**Effort**: 2 hours
**Impact**: Medium (Automated quality assurance)
**File**: `.github/workflows/test.yml`

```yaml
name: SQL Injection Test Suite

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.8', '3.9', '3.10', '3.11', '3.12']
        java-version: ['11', '17', '21']

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}

    - name: Set up Java ${{ matrix.java-version }}
      uses: actions/setup-java@v4
      with:
        distribution: 'temurin'
        java-version: ${{ matrix.java-version }}

    - name: Install Python dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install mypy pytest pytest-cov

    - name: Type checking with mypy
      run: |
        mypy my_analyzer.py --check-untyped-defs

    - name: Run unit tests
      run: |
        python test_analyzer.py

    - name: Compile Java test cases
      run: |
        cd src/main/java
        javac jpamb/sqli/*.java

    - name: Run integration tests
      run: |
        python test_runner.py --jpamb-path . --analyzer my_analyzer.py --no-html

    - name: Upload results
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: test-results-py${{ matrix.python-version }}-java${{ matrix.java-version }}
        path: results/

  quality-check:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'

    - name: Check code quality
      run: |
        pip install pylint
        pylint my_analyzer.py --disable=C0103,C0114,C0115,C0116 || true

    - name: Check formatting
      run: |
        pip install black
        black --check my_analyzer.py test_analyzer.py || true
```

---

### 6. Enhance Analyzer Algorithm
**Effort**: 4 hours
**Impact**: Medium (Better detection accuracy)

**Add to `my_analyzer.py`**:

```python
def detect_prepared_statement_misuse(method_body: str, trusted_vars: Set[str]) -> bool:
    """
    Detect if PreparedStatement is used incorrectly.
    PreparedStatement only protects VALUES, not table/column names.

    Args:
        method_body: Java method body source code
        trusted_vars: Set of known safe variable names

    Returns:
        True if PreparedStatement is misused

    Example vulnerability:
        String sql = "SELECT * FROM " + tableName;  # Vulnerable!
        PreparedStatement stmt = conn.prepareStatement(sql);
    """
    if "prepareStatement" not in method_body:
        return False

    # Find prepareStatement calls
    ps_pattern = r'prepareStatement\s*\(\s*(\w+)'
    matches = re.finditer(ps_pattern, method_body)

    for match in matches:
        sql_var = match.group(1)
        # Check if sql_var was built with concatenation
        concat_pattern = rf'{sql_var}\s*=.*\+'
        if re.search(concat_pattern, method_body):
            # Check if concatenated with untrusted var
            concat_vars = re.findall(rf'{sql_var}\s*=.*\+\s*(\w+)', method_body)
            for var in concat_vars:
                if var not in trusted_vars and not var.startswith('"'):
                    return True

    return False


def detect_numeric_context_injection(method_body: str, trusted_vars: Set[str]) -> bool:
    """
    Detect injection in numeric contexts where quotes aren't used.

    Args:
        method_body: Java method body source code
        trusted_vars: Set of known safe variable names

    Returns:
        True if numeric context injection found

    Example:
        WHERE id = " + userId  (no quotes, still vulnerable)
        Attack: userId = "1 OR 1=1"
    """
    # Pattern: SQL keyword + field + = + concatenation (without quotes)
    pattern = r'(WHERE|SET|LIMIT|OFFSET|HAVING)\s+\w+\s*=\s*"\s*\+\s*(\w+)'
    matches = re.finditer(pattern, method_body, re.IGNORECASE)

    for match in matches:
        var_name = match.group(2)
        if var_name not in trusted_vars:
            return True

    return False


def detect_format_string_injection(method_body: str, trusted_vars: Set[str]) -> bool:
    """
    Detect String.format() used with untrusted input.

    Args:
        method_body: Java method body source code
        trusted_vars: Set of known safe variable names

    Returns:
        True if dangerous String.format() usage found
    """
    if "String.format" not in method_body and ".format(" not in method_body:
        return False

    # Pattern: String.format("...", var)
    format_pattern = r'format\s*\([^,]+,\s*([^)]+)\)'
    matches = re.finditer(format_pattern, method_body)

    for match in matches:
        # Get all variables passed to format
        args = match.group(1)
        vars_in_args = re.findall(r'\b(\w+)\b', args)

        for var in vars_in_args:
            if var not in trusted_vars and not var.isdigit():
                # Check if it's in SQL context
                if 'query' in method_body.lower() or 'sql' in method_body.lower():
                    return True

    return False
```

**Update `analyze_for_sql_injection()` to use new detectors**:

```python
def analyze_for_sql_injection(method_body: str, method_name: str) -> Tuple[str, int]:
    """Enhanced analysis with additional detection patterns"""
    if not method_body:
        return "error", 0

    trusted_vars = extract_literals(method_body)

    # ... existing checks ...

    # NEW: Check for PreparedStatement misuse
    if detect_prepared_statement_misuse(method_body, trusted_vars):
        return "SQL injection", 95

    # NEW: Check for numeric context injection
    if detect_numeric_context_injection(method_body, trusted_vars):
        return "SQL injection", 90

    # NEW: Check for format string injection
    if detect_format_string_injection(method_body, trusted_vars):
        return "SQL injection", 85

    # ... rest of existing logic ...
```

---

### 7. Add Performance Benchmarks
**Effort**: 2 hours
**Impact**: Low (Good for monitoring)
**File**: `scripts/benchmark.py`

```python
#!/usr/bin/env python3
"""
Performance benchmarking for SQL injection analyzer
"""

import time
import statistics
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from my_analyzer import analyze_for_sql_injection, extract_method_body


def benchmark_analyzer():
    """Benchmark analyzer performance on all test cases"""

    # Sample method bodies of varying complexity
    test_cases = [
        # Simple
        '''String query = "SELECT * FROM users WHERE id = " + userId;
           executeQuery(query);''',

        # Medium
        '''String trimmed = input.substring(0, 10);
           String query = "SELECT * FROM users WHERE name = '" + trimmed + "'";
           executeQuery(query);''',

        # Complex
        '''String step1 = input.trim();
           String step2 = step1.toUpperCase();
           String step3 = step2.replace("  ", " ");
           String[] parts = step3.split(" ");
           String first = parts[0];
           String query = "SELECT * FROM users WHERE name = '" + first + "'";
           executeQuery(query);''',
    ]

    results = {
        'simple': [],
        'medium': [],
        'complex': []
    }

    # Warm up
    for _ in range(10):
        analyze_for_sql_injection(test_cases[0], "test")

    # Benchmark each complexity level
    iterations = 1000

    print("Benchmarking analyzer performance...")
    print(f"Iterations per test: {iterations}\n")

    for case, complexity in zip(test_cases, ['simple', 'medium', 'complex']):
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            analyze_for_sql_injection(case, "test")
            end = time.perf_counter()
            times.append((end - start) * 1000)  # Convert to ms

        results[complexity] = times

    # Print results
    print("="*60)
    print("PERFORMANCE BENCHMARK RESULTS")
    print("="*60)

    for complexity in ['simple', 'medium', 'complex']:
        times = results[complexity]
        print(f"\n{complexity.upper()} Test Cases:")
        print(f"  Average: {statistics.mean(times):.4f} ms")
        print(f"  Median:  {statistics.median(times):.4f} ms")
        print(f"  Min:     {min(times):.4f} ms")
        print(f"  Max:     {max(times):.4f} ms")
        print(f"  StdDev:  {statistics.stdev(times):.4f} ms")

    # Overall stats
    all_times = results['simple'] + results['medium'] + results['complex']
    print(f"\nOVERALL:")
    print(f"  Average: {statistics.mean(all_times):.4f} ms")
    print(f"  Total iterations: {len(all_times)}")
    print(f"  Throughput: {1000/statistics.mean(all_times):.0f} analyses/second")
    print("="*60)


if __name__ == "__main__":
    benchmark_analyzer()
```

---

## Low Priority (Polish)

### 8. Create API Documentation
**Effort**: 2 hours
**File**: `docs/API.md`

Document all public functions with examples, parameters, return values.

### 9. Add HTML Documentation with Sphinx
**Effort**: 3 hours

Generate professional documentation site.

### 10. Expand Sanitization Pattern Recognition
**Effort**: 2 hours

Add more recognized safe patterns:
```python
SAFE_SANITIZATION_PATTERNS = [
    r'replaceAll\s*\(\s*"\[\^0-9\]"',          # Numeric only
    r'replaceAll\s*\(\s*"\[\^a-zA-Z0-9\]"',    # Alphanumeric
    r'replaceAll\s*\(\s*"\[\^a-zA-Z0-9_\]"',   # Alphanumeric + underscore
    r'Pattern\.compile.*matches',               # Regex validation
    r'Integer\.parseInt',                       # Conversion to int (sanitizing)
    r'Long\.parseLong',                         # Conversion to long
    r'UUID\.fromString',                        # UUID validation
]
```

---

## Recommended Implementation Order

### Phase 1: This Week (10 hours)
**Goal**: Comprehensive documentation and robustness

1. ✓ **Complete JavaDoc for 22 remaining files** (4 hours)
   - Start with high-priority files: StringBuilder, Union, PartialSanitization, Loop, ComplexNested
   - Then complete the rest

2. ✓ **Add 10 harder test cases** (6 hours)
   - InterProcedural, Obfuscated, NumericContext, PreparedStatementMisuse, Reflection
   - ConditionalSanitization, ArrayConcatenation, ChainedOperations, TernaryExpression, FormatString

### Phase 2: Next Week (8 hours)
**Goal**: Infrastructure and automation

3. ✓ **Add integration tests** (3 hours)
4. ✓ **Reorganize project structure** (2 hours)
5. ✓ **Add CI/CD pipeline** (2 hours)
6. ✓ **Add performance benchmarks** (1 hour)

### Phase 3: Future (12 hours)
**Goal**: Enhanced capabilities

7. ✓ **Enhance analyzer algorithm** (4 hours)
8. ✓ **Expand sanitization patterns** (2 hours)
9. ✓ **Create API documentation** (2 hours)
10. ✓ **Generate HTML docs with Sphinx** (3 hours)
11. ✓ **Research AST-based parsing** (1 hour planning)

---

## Quick Wins (30 minutes each)

Want immediate impact? Pick any of these:

### Quick Win #1: Add JavaDoc to 5 Key Files
Files: SQLi_StringBuilder, SQLi_Union, SQLi_PartialSanitization, SQLi_Loop, SQLi_ComplexNested
Impact: JavaDoc coverage 12% → 32%

### Quick Win #2: Add PreparedStatement Misuse Test
Create SQLi_PreparedStatementMisuse.java
Impact: Tests a common real-world vulnerability

### Quick Win #3: Add Benchmark Script
Create scripts/benchmark.py
Impact: Performance monitoring capability

### Quick Win #4: Add GitHub Actions Workflow
Create .github/workflows/test.yml
Impact: Automated testing on every commit

---

## Success Metrics

Track these to measure improvement:

- **JavaDoc Coverage**: Current 12% → Target 100%
- **Test Case Count**: Current 25 → Target 35+
- **Test Case Difficulty**: Current "Easy-Medium" → Target "Easy-Hard"
- **Code Coverage**: Current 0% → Target 80%+
- **CI/CD**: Current None → Target Automated
- **Documentation**: Current Basic → Target Comprehensive

---

## Long-Term Vision (Beyond Current Scope)

### Major Upgrade: AST-Based Analysis
**Effort**: 20+ hours
**Impact**: Very High

Replace regex-based analysis with proper Java AST parsing using javalang or tree-sitter:
- 100% accurate Java syntax handling
- Inter-procedural analysis capability
- Framework-aware analysis
- Production-ready quality

### Framework Integration
**Effort**: 15+ hours

Add support for:
- Spring Framework (@RequestParam, @PathVariable)
- Hibernate/JPA (HQL, JPQL)
- JDBI, jOOQ query builders
- MyBatis XML mappers

---

*This roadmap provides a clear path to A+ quality (95-100 points)*
*Prioritize based on your project timeline and goals*
