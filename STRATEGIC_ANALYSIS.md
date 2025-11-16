# Strategic Analysis: Bytecode vs Source-Based Taint Analysis

**Date:** November 16, 2025
**Purpose:** Determine minimal necessary improvements before merging sqli-test-suite
**Author:** DTU Compute Group 4

---

## Executive Summary

**Recommendation:** **Continue with source-based analysis, add targeted improvements**

**Key Findings:**
1. ❌ **Bytecode analysis NOT necessary** for SQL injection detection
2. ✅ **Source-based can handle all 25 test cases** with targeted additions
3. ✅ **3 specific improvements needed:** StringBuilder, method parameters, executeQuery sink
4. ⏱️ **Estimated implementation time:** 2-3 hours (vs 20-30 hours for bytecode)

---

## Research Findings

### 1. Analysis of sqli-test-suite Branch

**Test Suite Composition:** 25 test cases across 5 categories

| Category | Count | Patterns Required |
|----------|-------|-------------------|
| Basic Concatenation | 5 | ✅ Already have (string concat) |
| String Operations | 5 | ✅ Already have (substring, replace, trim, case, split) |
| StringBuilder | 3 | ❌ **MISSING** - Need to add |
| Control Flow | 5 | ⚠️ Partial (sequential ok, loops/branches need work) |
| Real World | 7 | ⚠️ Partial (need parameter tracking) |

**Critical Missing Capabilities:**
1. **StringBuilder/StringBuffer tracking** - 3 tests fail without this
2. **Method parameters as sources** - Tests use `vulnerable(String userId)` not `getParameter()`
3. **executeQuery() sink** - Tests use local method, not `Statement.execute()`

**Current Analyzer Status:**
- ✅ Detects literal strings (trusted)
- ✅ Detects getParameter() calls (untrusted)
- ✅ Tracks concatenation
- ✅ Detects SQL sinks
- ❌ **Doesn't handle StringBuilder/StringBuffer**
- ❌ **Doesn't track method parameters**
- ❌ **Doesn't recognize executeQuery() as sink**

---

### 2. Bytecode vs Source-Based Analysis

#### Bytecode Analysis

**How it would work:**
```python
# Track taint on JVM stack and locals
def analyze_bytecode(methodid):
    taint_state = {
        'stack': [],      # Taint for each stack slot
        'locals': {},     # Taint for each local variable
        'heap': {}        # Taint for objects
    }

    for opcode in get_opcodes(methodid):
        match opcode:
            case jvm.InvokeVirtual(method="StringBuilder.append"):
                # Pop object ref and argument
                # Track taint through StringBuilder state
            case jvm.Load(index=i):
                # Push taint from local[i] to stack
            case jvm.Store(index=i):
                # Pop taint from stack to local[i]
```

**Pros:**
- ✅ More accurate (analyzes actual execution)
- ✅ Doesn't require source code
- ✅ Handles all Java constructs uniformly
- ✅ No ambiguity in semantics

**Cons:**
- ❌ **Much more complex** - 500-1000 lines vs 50-100 lines
- ❌ **Need heap tracking** for StringBuilder objects
- ❌ **Need to interpret method semantics** (String.concat, StringBuilder.append)
- ❌ **Control flow harder** - bytecode jumps vs source-level if/loops
- ❌ **String operations are method calls** - harder to identify
- ❌ **Implementation time:** 20-30 hours

#### Source-Based Analysis (Current Approach)

**How it works:**
```python
# Track taint on variables in source code
def analyze_source(methodid):
    taint_map = {}  # variable_name -> TaintedValue

    for statement in parse_statements(body):
        if is_literal_assignment(statement):
            taint_map[var] = TaintedValue.trusted(value)
        elif is_concatenation(statement):
            result = TaintTransfer.concat(operands)
            taint_map[var] = result
```

**Pros:**
- ✅ **Simpler to implement** - 50-100 additional lines
- ✅ **High-level patterns explicit** - concatenation is `+` operator
- ✅ **Easier to debug** - source is readable
- ✅ **Fast to extend** - add patterns incrementally
- ✅ **Implementation time:** 2-3 hours

**Cons:**
- ⚠️ Requires source code (acceptable for test suite)
- ⚠️ Might miss bytecode-only patterns (rare in practice)
- ⚠️ Need to handle each source construct (but finite set)

---

### 3. What Do We Actually Need?

**Analysis of 25 Test Cases:**

Looking at the test suite patterns, here's what's actually required:

#### ✅ **Already Have (15/25 cases)**
- Direct string concatenation (`"SELECT" + userId`)
- String literals (trusted)
- String operations (substring, replace, trim, toUpperCase, toLowerCase)
- Basic source detection (getParameter)
- Basic sink detection (Statement.execute)

#### ❌ **Missing (10/25 cases)**

**1. StringBuilder/StringBuffer (3 cases)**
```java
StringBuilder sb = new StringBuilder();
sb.append("SELECT * FROM users WHERE id = ");
sb.append(userInput);  // Tainted!
String query = sb.toString();
```

**2. Method Parameters as Sources (7 cases)**
```java
public static void vulnerable(String userId) {
    // userId should be marked UNTRUSTED (it's a parameter)
    String query = "SELECT" + userId;
}
```

**3. executeQuery() Sink Recognition (all cases)**
```java
private static void executeQuery(String q) { ... }
executeQuery(query);  // Should be recognized as SQL sink
```

---

## Decision Matrix

| Criterion | Bytecode | Source-Based | Winner |
|-----------|----------|--------------|--------|
| **Complexity** | High (500-1000 LOC) | Low (50-100 LOC) | ✅ Source |
| **Implementation Time** | 20-30 hours | 2-3 hours | ✅ Source |
| **Handles Test Suite** | Yes | Yes (with 3 additions) | ✅ Source |
| **Accuracy** | High | Medium-High | ⚠️ Bytecode |
| **Debugging** | Hard | Easy | ✅ Source |
| **Extensibility** | Medium | High | ✅ Source |
| **Learning Value** | High | Medium | ⚠️ Bytecode |
| **Practical Value** | Medium | High | ✅ Source |

**Score:** Source-based: **6/8** | Bytecode: **2/8**

---

## Minimal Necessary Improvements

### Improvement 1: StringBuilder/StringBuffer Support

**Effort:** 1-2 hours
**Impact:** Handles 3 test cases
**Priority:** **HIGH**

**Implementation:**
```python
# Detect StringBuilder/StringBuffer creation
if node.type == "object_creation_expression":
    if "StringBuilder" in node.text or "StringBuffer" in node.text:
        var = get_assigned_var(node)
        taint_map[var] = TaintedValue.trusted("", source="string_builder")
        builder_map[var] = []  # Track what's appended

# Detect append() calls
elif is_method_call(node, "append"):
    obj_var = get_object_var(node)
    arg = get_argument(node)
    if obj_var in builder_map:
        arg_taint = get_taint(arg, taint_map)
        builder_map[obj_var].append(arg_taint)

# Detect toString() calls
elif is_method_call(node, "toString"):
    obj_var = get_object_var(node)
    if obj_var in builder_map:
        result = TaintTransfer.concat(*builder_map[obj_var])
        taint_map[result_var] = result
```

### Improvement 2: Method Parameter Tracking

**Effort:** 30 minutes
**Impact:** Handles 7 test cases
**Priority:** **HIGH**

**Implementation:**
```python
def extract_method_parameters(method_node):
    """Mark all method parameters as UNTRUSTED by default"""
    params = method_node.child_by_field_name("parameters")
    for param in params.children:
        if param.type == "formal_parameter":
            param_name = get_parameter_name(param)
            # All parameters are untrusted (they come from external sources)
            taint_map[param_name] = TaintedValue.untrusted(
                "parameter",
                source="method_parameter"
            )
```

### Improvement 3: executeQuery() Sink Recognition

**Effort:** 15 minutes
**Impact:** Handles all 25 test cases
**Priority:** **HIGH**

**Implementation:**
```python
# In sources.py, add to SQL_SINKS:
SQL_SINKS: Set[str] = {
    "java.sql.Statement.execute",
    "java.sql.Statement.executeQuery",
    "java.sql.Statement.executeUpdate",
    "java.sql.Connection.prepareStatement",
    "executeQuery",  # Add simple name match
}

# In extract_method_name():
if method_name == "executeQuery":
    return "java.sql.Statement.executeQuery"
```

---

## Optional Improvements (Lower Priority)

### Optional 1: Control Flow (Loops/Conditionals)

**Effort:** 2-3 hours
**Impact:** More accurate for 5 test cases (but simple analysis might work)
**Priority:** **MEDIUM**

**Why Optional:**
- Our conservative approach (if ANY branch is tainted, result is tainted) might handle most cases
- Can add later if needed

### Optional 2: Interprocedural Analysis

**Effort:** 4-6 hours
**Impact:** Handles cross-method taint flow
**Priority:** **LOW**

**Why Optional:**
- All 25 test cases are intraprocedural (single method)
- Not needed for current test suite
- Can add in future work

---

## Comparison with Existing Analyzer

The sqli-test-suite has `my_analyzer.py` which:
- Uses **syntactic pattern matching** (not true taint analysis)
- Tracks which variables are assigned literals
- Checks if query contains non-literal variables
- **Achieved 96% accuracy (24/25 correct)**

Our taint-based analyzer:
- Uses **proper variable-level taint tracking**
- Propagates taint through operations
- More theoretically sound
- Should achieve **≥96% accuracy** with the 3 improvements

**Key Advantage of Our Approach:**
- Handles escaping correctly (escaped data still tainted)
- More extensible (proper taint propagation model)
- Better foundation for future work

---

## Recommended Implementation Plan

### Phase 1: Add 3 Critical Improvements (2-3 hours)

**Step 1.1: StringBuilder/StringBuffer (1.5 hours)**
- Add builder tracking data structure
- Detect StringBuilder/StringBuffer creation
- Track append() calls
- Handle toString() conversion
- Test on SQLi_StringBuilder.java

**Step 1.2: Method Parameters (30 min)**
- Extract method parameters
- Mark all parameters as UNTRUSTED
- Test on SQLi_DirectConcat.java

**Step 1.3: executeQuery() Sink (15 min)**
- Add executeQuery to SQL_SINKS
- Update sink detection logic
- Test on all test cases

**Step 1.4: Testing (30 min)**
- Run analyzer on 3-5 representative test cases
- Verify correct detection
- Fix any issues

### Phase 2: Run Full Evaluation (1 hour)

**Step 2.1: Merge sqli-test-suite**
- Merge branch into feature/taint-analysis
- Resolve any conflicts

**Step 2.2: Run Test Suite**
- Run analyzer on all 25 test cases
- Record results (TP, FP, FN, TN)
- Calculate metrics (precision, recall, F1)

**Step 2.3: Compare with Baseline**
- Run my_analyzer.py on same cases
- Compare detection rates
- Document differences

### Phase 3: Document Results (30 min)

**Step 3.1: Create Report**
- Detection rates
- Comparison with syntactic baseline
- Analysis of any failures
- Lessons learned

**Total Time:** ~4 hours

---

## Why NOT Bytecode (Detailed Justification)

### 1. Complexity vs Benefit

**Bytecode Complexity:**
- Need to track taint on JVM stack (not just variables)
- Need to model heap for StringBuilder objects
- Need to interpret 20+ opcode types
- Need to handle method calls with taint propagation
- Need to implement abstract interpretation framework

**Example: StringBuilder in Bytecode**
```
// Source: sb.append("SELECT")
new java/lang/StringBuilder        // Stack: [StringBuilder_ref]
dup                                // Stack: [StringBuilder_ref, StringBuilder_ref]
ldc "SELECT"                       // Stack: [StringBuilder_ref, StringBuilder_ref, "SELECT"]
invokevirtual StringBuilder.append // Stack: [StringBuilder_ref]
```

To track this, we'd need:
1. Track NEW instruction → allocate object in abstract heap
2. Track DUP → duplicate taint on stack
3. Track LDC → push literal (trusted) taint
4. Track INVOKEVIRTUAL → update object taint state in heap
5. Maintain heap mapping: object_id → taint_state

**Source Complexity:**
```python
# Source: sb.append("SELECT")
if is_method_call(node, "append"):
    arg_taint = TaintedValue.trusted("SELECT")
    builder_taint.append(arg_taint)
```

Much simpler!

### 2. Time Investment

**Bytecode Implementation:**
- Abstract interpretation framework: 6-8 hours
- Opcode handlers: 8-10 hours
- Heap tracking: 4-6 hours
- Testing & debugging: 6-8 hours
- **Total: 24-32 hours**

**Source Implementation:**
- StringBuilder tracking: 1.5 hours
- Parameter tracking: 0.5 hours
- Sink detection: 0.25 hours
- Testing: 0.5 hours
- **Total: 2.75 hours**

**Time savings: 21-29 hours** (87-91% reduction)

### 3. Learning Value vs Practical Value

**Bytecode Pros:**
- Learn abstract interpretation
- Learn JVM internals
- More theoretically interesting

**Bytecode Cons:**
- **Doesn't improve detection rate** for SQL injection
- Over-engineered for the problem
- Harder to extend/maintain
- Less time for evaluation and comparison

**Verdict:** Bytecode is academically interesting but practically unnecessary

---

## Addressing User's Concerns

### "Rewrite analyzer to use bytecode"

**Analysis:** Not recommended because:
1. **No benefit for detection rate** - source-based handles all test cases
2. **10x time investment** - 24-32 hours vs 2-3 hours
3. **Higher complexity** - harder to debug and extend
4. **Opportunity cost** - time better spent on evaluation and comparison

**Alternative:** Add targeted source-based improvements (3 items, 2-3 hours)

### "Add more string operations"

**Analysis:** Already have most operations!

**Current support (in TaintTransfer):**
- ✅ concat()
- ✅ substring()
- ✅ replace()
- ✅ trim()
- ✅ to_lower()
- ✅ to_upper()
- ✅ split()
- ✅ join()

**Missing:**
- ❌ StringBuilder.append() - **NEED TO ADD**
- ❌ StringBuffer.append() - **NEED TO ADD**

**Recommendation:** Add StringBuilder/StringBuffer support (already in plan)

### "Add interprocedural analysis"

**Analysis:** Not needed for current test suite

**Evidence:**
- All 25 test cases are single-method
- No cross-method taint flow in test suite
- Can add later if needed

**Recommendation:** Skip for now, add in future work if needed

### "Run evaluation (syntactic vs taint comparison)"

**Analysis:** YES, this is critical!

**Plan:**
1. Add 3 improvements to analyzer (2-3 hours)
2. Merge sqli-test-suite
3. Run both analyzers on all 25 cases
4. Compare results, calculate metrics
5. Document findings

**Recommendation:** Prioritize this after improvements

---

## Final Recommendation

### Do This (High Value, Low Effort):

1. ✅ **Add StringBuilder/StringBuffer support** (1.5 hours)
2. ✅ **Add method parameter tracking** (0.5 hours)
3. ✅ **Add executeQuery() sink** (0.25 hours)
4. ✅ **Merge sqli-test-suite branch** (0.5 hours)
5. ✅ **Run full evaluation** (1 hour)
6. ✅ **Compare with syntactic baseline** (1 hour)
7. ✅ **Document results** (0.5 hours)

**Total: ~5 hours**

### Don't Do This (Low Value, High Effort):

1. ❌ **Rewrite to bytecode** - 24-32 hours, no benefit
2. ❌ **Add interprocedural analysis** - 4-6 hours, not needed for test suite
3. ❌ **Add complex control flow** - 2-3 hours, conservative approach works

---

## Success Metrics

**After implementing improvements, we should achieve:**

| Metric | Target | Justification |
|--------|--------|---------------|
| **Detection Rate** | ≥96% (24/25) | Match or beat syntactic baseline |
| **False Positive Rate** | ≤4% (1/25) | Match or beat baseline |
| **True Positives** | 25/25 | Detect all vulnerable cases |
| **True Negatives** | 24/25 | Correctly identify safe cases |
| **Implementation Time** | <6 hours | Minimal, focused improvements |

**Comparison with Baseline:**
- Our approach: Proper taint tracking, theoretically sound
- Baseline: Pattern matching, less robust
- Expected: Similar detection rate, better theoretical foundation

---

## Conclusion

**Strategic Decision: Continue with source-based analysis + 3 targeted improvements**

**Rationale:**
1. ✅ **Minimal effort** - 2-3 hours vs 24-32 hours for bytecode
2. ✅ **Same coverage** - Handles all 25 test cases
3. ✅ **Better ROI** - More time for evaluation and comparison
4. ✅ **Maintainable** - Simpler code, easier to extend
5. ✅ **Practical** - Focuses on what matters for SQL injection detection

**Next Steps:**
1. Implement 3 improvements (2-3 hours)
2. Test on sample cases (30 min)
3. Merge sqli-test-suite (30 min)
4. Run full evaluation (1 hour)
5. Compare with baseline (1 hour)
6. Document results (30 min)

**Total timeline: 1-2 days of focused work**

---

**Document Status:** ✅ COMPLETE
**Decision:** Proceed with source-based improvements, skip bytecode rewrite
**Owner:** DTU Compute Group 4
**Date:** November 16, 2025