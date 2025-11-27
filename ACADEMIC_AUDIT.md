# Academic Audit - Paper Publication Readiness

**Purpose:** Ensure our paper is academically rigorous, honest, and publishable
**Date:** November 27, 2025

---

## 1. Potential Overfitting Concerns

### Issue 1: Self-Created Benchmark (HIGH RISK)

**Problem:** We created both the analyzer AND the test suite.

**Risk:** Unconscious bias - we may have designed test cases that our analyzer can handle.

**Evidence of potential overfitting:**
- All 55+ test files were created by our team
- Test patterns may reflect our understanding of the analyzer
- No external validation

**Mitigation Required:**
1. **Run on SecuriBench Micro** - 96 test cases, 10 categories
   - Download: https://github.com/too4words/securibench-micro
   - Focus on SQL injection test cases

2. **Run on Juliet CWE-89** - 2,280 SQL injection test cases
   - Download: https://samate.nist.gov/SARD/test-suites/111
   - Industry standard benchmark

3. **Compare with existing tools** - SpotBugs, SonarQube, Semgrep
   - Run same benchmarks on all tools
   - Report comparative results

### Issue 2: Test-Specific Code Removed (MITIGATED)

**Previous problem:** We had benchmark-specific matching like:
```python
# REMOVED - was overfitting
if method_name == "executeQuery":  # Simple name matching
if method_name == "getParameter":  # Simple name matching
```

**Current state:** Using real JDBC signatures only:
```python
SINKS = {
    "java.sql.Statement.execute",
    "java.sql.Statement.executeQuery",
    "java.sql.Statement.executeUpdate",
    "java.sql.Connection.prepareStatement",
}
```

**Status:** ✅ FIXED - No longer matches arbitrary method names

### Issue 3: Ground Truth Accuracy (MEDIUM RISK)

**Problem:** Our labels (vulnerable/safe) are based on our own analysis.

**Risk:** Labels may be incorrect.

**Mitigation:**
- [ ] Manual review of all 118 method labels
- [ ] Have second team member verify labels
- [ ] Document labeling methodology in paper

---

## 2. Soundness Analysis

### Abstract Interpretation Foundation

**Question:** Is our analysis sound (no false negatives in theory)?

**Answer:** No - we are NOT sound. This is honest and acceptable for a practical tool.

**Why we're not sound:**
1. **Intraprocedural only** - Taint can escape through method calls
2. **No alias analysis** - Object references not tracked precisely
3. **Conservative heap** - May miss some heap-based flows

**What to claim in paper:**
> "Our analysis is designed for practical SQL injection detection, not formal soundness. We prioritize precision (low false positives) over recall (catching all bugs)."

### Transfer Function Correctness

**Verify each transfer function is logically correct:**

| Function | Logic | Status |
|----------|-------|--------|
| `transfer_push` | Constants are TRUSTED | ✅ Correct |
| `transfer_load` | Load preserves taint from locals | ✅ Correct |
| `transfer_store` | Store preserves taint to locals | ✅ Correct |
| `transfer_invoke_virtual` | String concat propagates taint | ✅ Correct |
| `transfer_invoke_interface` | JDBC sink detection | ✅ Correct |
| `transfer_invoke_dynamic` | invokedynamic for string concat | ✅ Correct |

---

## 3. Comparison with Other Tools

### Required Comparisons

For a publishable paper, we MUST compare with at least 2-3 existing tools:

| Tool | Type | How to Compare |
|------|------|----------------|
| **SpotBugs** | Static analysis | Run on same test suite |
| **SonarQube** | Static analysis | Run on same test suite |
| **Semgrep** | Pattern matching | Run on same test suite |
| **FindSecBugs** | SpotBugs plugin for security | Run on same test suite |

### Expected Comparison Table (for paper)

```
| Tool | Accuracy | Precision | Recall | FP Rate |
|------|----------|-----------|--------|---------|
| Our Tool | 81.4% | 88.4% | 69.1% | 7.9% |
| SpotBugs | [TODO] | [TODO] | [TODO] | [TODO] |
| SonarQube | [TODO] | [TODO] | [TODO] | [TODO] |
| Semgrep | [TODO] | [TODO] | [TODO] | [TODO] |
```

---

## 4. Threats to Validity

### Internal Validity

1. **Ground truth accuracy:** Our vulnerability labels may be incorrect
   - Mitigation: Second reviewer verification

2. **Implementation bugs:** Analyzer may have bugs affecting results
   - Mitigation: Unit tests for transfer functions

3. **Test suite coverage:** May not cover all SQL injection patterns
   - Mitigation: Run on external benchmarks

### External Validity

1. **Synthetic test cases:** Our test cases are small (10-30 lines)
   - Real code is much more complex
   - Mitigation: Acknowledge limitation, test on real projects

2. **No framework support:** Can't analyze Spring, Hibernate, JPA
   - Most production Java uses frameworks
   - Mitigation: Acknowledge as future work

3. **Intraprocedural limitation:** Real vulnerabilities often span methods
   - Mitigation: Acknowledge limitation

### Construct Validity

1. **Metric definitions:** We use standard metrics (precision, recall, F1)
   - No concerns here

2. **Vulnerability definition:** We define "vulnerable" as tainted data reaching sink
   - This is standard for taint analysis

---

## 5. Reproducibility Checklist

### For Paper Artifact

- [ ] All code in public repository
- [ ] README with setup instructions
- [ ] All dependencies documented (uv, Python 3.13+, Java 17+)
- [ ] Test cases included
- [ ] Evaluation script that reproduces results
- [ ] Docker/container for reproducibility

### For External Benchmarks

- [ ] Instructions to run on SecuriBench Micro
- [ ] Instructions to run on Juliet CWE-89
- [ ] Scripts to collect and compare results

---

## 6. Paper Claims Audit

### Claims We CAN Make (Supported by Evidence)

✅ "Our bytecode-level taint analyzer achieves 81.4% accuracy on 118 test methods"

✅ "We achieve 88.4% precision, indicating low false positive rate"

✅ "Our analyzer uses real JDBC method signatures, not test-specific patterns"

✅ "The implementation is 1329 lines, significantly smaller than industrial tools"

✅ "Analysis completes in under 1 second per method"

### Claims We CANNOT Make (Without More Evidence)

❌ "Our tool is better than SpotBugs/SonarQube" - Need comparison data

❌ "Our tool works on real-world applications" - Only tested on synthetic cases

❌ "Our tool detects most SQL injection vulnerabilities" - 69.1% recall is not "most"

❌ "Our approach is sound" - We miss vulnerabilities by design

### Claims That Need Qualification

⚠️ "Our precision is better than typical SAST tools (40-60%)"
   → Add: "based on reported industry benchmarks [cite Bermejo Higuera 2020]"

⚠️ "Bytecode analysis enables analysis without source code"
   → Add: "for applications where bytecode is available"

---

## 7. Action Items for Publication

### MUST DO (Before Submission)

1. **Run on SecuriBench Micro** (2-4 hours)
   - Download benchmark
   - Convert to our format
   - Run analyzer
   - Report results

2. **Run at least one comparison tool** (2-4 hours)
   - Easiest: Semgrep with SQL injection rules
   - Run on our test suite
   - Report comparative results

3. **Review all ground truth labels** (1-2 hours)
   - Go through all 118 methods
   - Verify vulnerable/safe labels are correct

4. **Add threats to validity section** (30 min)
   - Internal, external, construct validity
   - Be honest about limitations

### SHOULD DO (Improves Paper Quality)

5. **Run on 2+ comparison tools**
   - SpotBugs with FindSecBugs
   - SonarQube

6. **Run on subset of Juliet CWE-89**
   - At least 100 test cases
   - Shows generalization

7. **Test on one real-world project**
   - Small open-source project
   - Shows practical applicability

### NICE TO HAVE (Time Permitting)

8. Add more JDBC sinks (PreparedStatement, CallableStatement)
9. Add more sources (Cookie, Session)
10. Performance benchmarking (time per method)

---

## 8. Honest Limitations Section (For Paper)

### What to Include in Discussion Section

```
Our analysis has several limitations:

1. **Intraprocedural Analysis:** We analyze methods independently and cannot
   track taint flow across method calls. This limits detection of vulnerabilities
   where user input enters through a different method.

2. **Lambda Expressions:** Java lambdas compile to separate synthetic methods,
   which our current implementation does not analyze. This accounts for 4 of
   our 17 false negatives.

3. **Switch Expressions:** Java 14+ switch expressions use tableswitch/lookupswitch
   bytecode instructions that we handle only partially.

4. **No Framework Support:** We do not model Spring, Hibernate, or JPA frameworks,
   which limits applicability to framework-heavy applications.

5. **Synthetic Test Suite:** Our primary evaluation uses test cases we designed.
   While we removed test-specific code to avoid overfitting, results may not
   generalize to production code. [External benchmark results here]
```

---

## 9. Summary

### Current Readiness: 70%

| Aspect | Status | Action |
|--------|--------|--------|
| Analyzer implementation | ✅ Complete | - |
| Test suite | ✅ Complete | Review labels |
| No overfitting code | ✅ Fixed | - |
| External benchmark | ❌ Missing | Run SecuriBench |
| Tool comparison | ❌ Missing | Run Semgrep/SpotBugs |
| Threats to validity | ❌ Missing | Write section |
| Reproducibility | ⚠️ Partial | Add Docker |

### Final Recommendation

**The paper is publishable IF:**
1. We add external benchmark results (SecuriBench Micro or Juliet)
2. We add at least one tool comparison
3. We honestly discuss limitations and threats to validity

**Without these, reviewers will likely reject with:**
- "No external validation"
- "No comparison with existing tools"
- "May be overfitted to custom benchmark"

---

**Document Status:** Ready for team review
**Next Steps:** Execute action items in priority order
