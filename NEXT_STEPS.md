# Next Steps - Minimal Incremental Plan

**Current Status:** Core taint tracking implemented and tested (68 tests passing)
**Branch:** `feature/taint-analysis`
**Date:** November 16, 2025

---

## 📊 What We Have Now

### ✅ Completed
- **Core taint module** (`jpamb/taint/`)
  - TaintedValue class
  - TaintTransfer functions (7 operations)
  - SourceSinkDetector
- **Unit tests** (68 tests, all passing)
  - test_taint_value.py (15 tests)
  - test_taint_transfer.py (45 tests)
  - test_taint_sources.py (22 tests)
- **Integration tests** (test_taint_integration.py, 50+ tests)
- **Documentation**
  - CORE_IMPLEMENTATION_SUMMARY.md
  - demo_taint.py (working demonstration)
  - MASTER_PLAN.md (overall strategy)

### ❌ What's Missing

1. **No actual analyzer** that uses taint tracking on real Java code
2. **No SQLi test cases** in current branch (they're in `feature/sqli-test-suite`)
3. **No integration** with JPAMB test framework
4. **No comparison** with syntactic baseline

---

## 🎯 Minimal Next Steps (Build on Base)

### Principle: **Start Small, Prove It Works, Iterate**

### Step 1: Create Minimal Taint Analyzer ⭐ START HERE

**Goal:** Simple analyzer that detects SQL injection using our taint tracking

**Scope:**
- Read Java source code (not bytecode - simpler)
- Track taint through simple patterns
- Detect SQL execution with tainted data
- Output JPAMB-compatible predictions

**Architecture:**
```
Input: Method identifier (jpamb.cases.Simple.divideByZero:()I)
↓
1. Load Java source file
2. Extract method body
3. Parse for:
   - String literals → Mark TRUSTED
   - Method calls to sources → Mark UNTRUSTED
   - String concatenations → Apply taint transfer
   - SQL execution → Check if tainted
4. Output: "sql injection;XX%" or "ok;XX%"
```

**Implementation:** ~100-150 lines
**File:** `solutions/simple_taint_analyzer.py`
**Pattern:** Similar to existing `syntaxer.py` but with taint tracking

**Why this first:**
- Proves taint tracking works end-to-end
- Minimal complexity (source-based, not bytecode)
- Can test immediately
- Foundation for more complex analyzer

---

### Step 2: Create 3 Simple Test Cases

**Goal:** Minimal test suite to prove analyzer works

**Test cases:**
1. **Simple vulnerable** - Direct concatenation
2. **Simple safe** - All literals
3. **Escaped but unsafe** - Replace with escaping

**Implementation:**
- Create `test_simple_sqli.py` with 3 small test methods
- Manual ground truth labels
- Run analyzer, verify results

**Why minimal:**
- Don't need 25 cases to prove concept
- Can add more later
- Focus on getting pipeline working

---

### Step 3: Integration Test

**Goal:** Run analyzer through JPAMB framework

**Tasks:**
1. Make analyzer JPAMB-compatible (use `jpamb.getcase()`)
2. Test with `uv run jpamb test`
3. Verify output format matches expectations

**Success criteria:**
- Analyzer runs without errors
- Detects at least 1 vulnerability
- Produces correct output format

---

### Step 4: Document & Commit

**Goal:** Clean commit with working minimal analyzer

**Deliverables:**
- Working `simple_taint_analyzer.py`
- 3 passing test cases
- README update
- Commit message

---

## 📋 Detailed Step 1: Build Minimal Analyzer

### File Structure

```
solutions/simple_taint_analyzer.py
```

### Core Algorithm

```python
# Pseudocode
def analyze(method_id, input):
    # 1. Load source
    source = load_java_source(method_id)
    method_body = extract_method_body(source, method_id)

    # 2. Initialize taint map
    taint_map = {}  # var_name → TaintedValue

    # 3. Process statements
    for statement in parse_statements(method_body):
        if is_literal_assignment(statement):
            var, value = parse_assignment(statement)
            taint_map[var] = TaintedValue.trusted(value)

        elif is_source_call(statement):
            var = get_assigned_var(statement)
            taint_map[var] = TaintedValue.untrusted("user_input", source="http")

        elif is_concatenation(statement):
            result_var, vars = parse_concat(statement)
            values = [taint_map.get(v, TaintedValue.untrusted("unknown"))
                      for v in vars]
            taint_map[result_var] = TaintTransfer.concat(*values)

        elif is_sql_execution(statement):
            query_var = get_query_var(statement)
            if query_var in taint_map:
                if taint_map[query_var].is_tainted:
                    return "sql injection;100%"

    return "ok;100%"
```

### Implementation Strategy

**Phase A: Skeleton (30 min)**
- Copy structure from `syntaxer.py`
- Add imports for taint module
- Get basic source loading working

**Phase B: Literal Detection (30 min)**
- Find `String x = "literal"` patterns
- Mark as trusted in taint map

**Phase C: Source Detection (30 min)**
- Find `getParameter()` calls
- Mark as untrusted

**Phase D: Concat Tracking (45 min)**
- Find `x = y + z` patterns
- Apply TaintTransfer.concat()

**Phase E: Sink Detection (30 min)**
- Find `execute()` calls
- Check if query is tainted

**Phase F: Test (30 min)**
- Create simple test case
- Run analyzer
- Debug and fix

**Total: ~3 hours**

---

## 🔧 Technical Decisions

### 1. Source-Based vs Bytecode-Based

**Decision:** Start with **source-based**

**Why:**
- Simpler to parse (regex patterns)
- Faster to implement
- Existing examples (syntaxer.py)
- Can upgrade to bytecode later

**Tradeoff:**
- Less accurate (misses bytecode-only patterns)
- Requires source code
- But: Good enough for proof of concept

---

### 2. Full Interprocedural vs Intraprocedural

**Decision:** Start with **intraprocedural** (single method)

**Why:**
- Much simpler
- Faster implementation
- Catches majority of cases
- Can add interprocedural later

**Limitation:**
- Misses taint flow across methods
- But: SQL injection usually in same method

---

### 3. Complete String Ops vs Core Ops

**Decision:** Support **3 core operations** first

**Core:**
1. Concatenation (x = y + z)
2. Assignment (x = y)
3. Literal (x = "literal")

**Later:**
- substring, replace, trim, etc.
- Can add as needed

---

## 📈 Success Metrics (Minimal)

### For Step 1 (Analyzer)

| Metric | Target | How to Measure |
|--------|--------|----------------|
| **Compiles** | Yes | `python simple_taint_analyzer.py` |
| **Runs on 1 test** | Yes | Manual test |
| **Detects 1 vulnerability** | Yes | See output |
| **No false negative on obvious case** | Yes | Test basic concat |
| **Code quality** | Good | Type hints, docstrings |
| **Lines of code** | <200 | Keep it simple |

### For Step 2 (Test Cases)

| Metric | Target |
|--------|--------|
| **Test cases created** | 3 |
| **Ground truth defined** | Yes |
| **Analyzer runs on all** | Yes |

### For Step 3 (Integration)

| Metric | Target |
|--------|--------|
| **JPAMB compatible** | Yes |
| **Output format correct** | Yes |
| **Can run with `jpamb test`** | Yes |

---

## 🚫 What NOT to Do (Scope Creep)

❌ **Don't** implement all 25 test cases yet
❌ **Don't** add bytecode analysis yet
❌ **Don't** add visualization yet
❌ **Don't** add interprocedural analysis yet
❌ **Don't** compare with syntactic baseline yet
❌ **Don't** merge sqli-test-suite branch yet
❌ **Don't** optimize performance yet

**Do:** The minimal thing that proves it works!

---

## 📝 Step-by-Step Checklist

### Pre-work
- [x] Core taint module implemented
- [x] Core tests passing
- [ ] **Read existing analyzers** (syntaxer.py, interpreter.py)
- [ ] **Understand JPAMB interface** (jpamb.getcase())

### Step 1: Minimal Analyzer
- [ ] Create `solutions/simple_taint_analyzer.py`
- [ ] Implement source loading
- [ ] Implement literal detection → trusted
- [ ] Implement source detection → untrusted
- [ ] Implement concat tracking
- [ ] Implement sink detection
- [ ] Add JPAMB interface
- [ ] Add docstrings and type hints
- [ ] Test manually on 1 case

### Step 2: Test Cases
- [ ] Create 3 simple Java test methods
- [ ] Define expected outcomes
- [ ] Run analyzer on each
- [ ] Verify results match expectations

### Step 3: Integration
- [ ] Make JPAMB-compatible
- [ ] Test with `uv run jpamb test`
- [ ] Fix any format issues
- [ ] Document usage

### Step 4: Clean Up
- [ ] Code review (self)
- [ ] Add comments
- [ ] Update README
- [ ] Commit with good message
- [ ] Push to branch

---

## 🎯 Next-Next Steps (After Minimal Analyzer Works)

Once Steps 1-4 are complete and committed:

**Option A: Expand Test Suite**
- Merge sqli-test-suite branch
- Run analyzer on 25 cases
- Measure detection rate

**Option B: Add More Operations**
- Support substring, replace, trim
- Handle StringBuilder
- Improve accuracy

**Option C: Comparison**
- Run syntactic baseline
- Compare results
- Analyze differences

**Option D: Visualization**
- Show taint flow
- Highlight vulnerabilities
- Interactive demo

**Recommendation:** **Option A** (expand test suite)
- Most value
- Validates approach
- Enables evaluation

---

## 💡 Key Principles

1. **Minimal First** - Build smallest thing that works
2. **Test Early** - Verify each piece works before moving on
3. **Incremental** - Add one feature at a time
4. **Document** - Keep notes on what works/doesn't
5. **Commit Often** - Small, working commits
6. **Clean Code** - Type hints, docstrings, good names

---

## 🚀 Let's Start

**Next action: Implement Step 1 - Minimal Taint Analyzer**

Estimated time: 3 hours
Expected result: Working analyzer that detects 1 SQL injection

**Ready to build?**

---

**Document Status:** ✅ PLAN COMPLETE
**Next Step:** Create `solutions/simple_taint_analyzer.py`
**Owner:** Team
**Date:** November 16, 2025
