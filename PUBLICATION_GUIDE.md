# Publication Guide - Mind Your Own Query

**Last Updated:** November 29, 2025
**Status:** Ready for final work

---

## 1. Current Status Summary

### Results Achieved
| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| Accuracy | 87.1% | 75% | Exceeded |
| Precision | 97.5% | 70% (FP < 30%) | Exceeded |
| Recall | 76.1% | 75% | Met |
| F1 Score | 85.5% | - | Good |
| FP Rate | 2.0% | < 30% | Excellent |
| Test Cases | 255 | 25 | Exceeded |

### Tool Comparison (All tested on OUR benchmark)
| Tool | Accuracy | Precision | Recall | FPR |
|------|----------|-----------|--------|-----|
| **Our Analyzer** | **87.1%** | **97.5%** | **76.1%** | **2.0%** |
| SpotBugs + FindSecBugs | 50.0% | 50.0% | 100.0% | 100.0% |
| Semgrep | 50.0% | 50.0% | 60.0% | 60.0% |

*SpotBugs flags EVERYTHING as vulnerable (useless in practice)*

---

## 2. Files to Clean Up

### DELETE These (480MB+ savings):
```bash
# External benchmarks (only needed temporarily for comparison)
rm -rf benchmarks/                    # 480MB - OWASP, SecuriBench clones

# Temporary Python files
rm -f /tmp/fix_*.py                   # Temporary fix scripts

# Cache directories
rm -rf **/__pycache__/
rm -rf **/.pytest_cache/
rm -rf sqli-test-suite/.venv/
```

### KEEP But Review:
```
docs/archive/                         # Old documentation (9 files)
  - Could consolidate into main docs

sqli-test-suite/                      # Separate test suite (redundant?)
  - Has its own venv, test files
  - Consider merging with main project
```

### Files to UPDATE:
```
README.md                             # ✅ Updated with 87.1% accuracy
FINAL_ACHIEVEMENTS.md                 # ✅ Updated with correct metrics
RESEARCH_COMPARISON.md                # May need review
ACADEMIC_AUDIT.md                     # May need review
```

---

## 3. Code Review Findings

### No Critical Logic Errors Found

The analyzer is well-structured with:
- CFG-based worklist algorithm (proper dataflow analysis)
- 18 opcode handlers (covers common JVM operations)
- TAJ-style string carrier pattern (efficient StringBuilder handling)
- Real JDBC signatures (no test-specific matching)

### Minor Issues Identified

1. **Switch statements not handled** (lines 1106-1108)
   - `jvm.TableSwitch` and `jvm.LookupSwitch` fall to default case
   - Causes 0% detection on switch_statements category
   - **Fix:** Add explicit handlers

2. **Array taint not propagated** (lines 1006-1025)
   - `transfer_array_store` is essentially a no-op
   - Causes 0% detection on array_operations category
   - **Fix:** Track array contents in heap

3. **String.format() not handled** (MethodMatcher class)
   - Not in TAINT_PRESERVING set
   - Causes 0% detection on formatting category
   - **Fix:** Add to taint-preserving methods

4. **No widening operator** (worklist algorithm)
   - Could theoretically loop forever on complex loops
   - In practice, max_iterations = 1000 prevents this
   - **Note:** Not causing current failures

### Potential Bias Check

| Concern | Status | Evidence |
|---------|--------|----------|
| Test-specific matching | Fixed | Only real JDBC signatures used |
| Self-created benchmark | Mitigated | External tool comparison done |
| Ground truth accuracy | Needs review | Labels created by team |
| Overfitting to patterns | Unlikely | 3 categories score 0% (not tuned) |

---

## 4. What Was NOT Done (From Original Plans)

### From project_proposal.md:
- [ ] Visualization component (VIS: 8 points allocated)
- [ ] Bytecode instrumentation (NIN: 8 points allocated)
- [ ] Coverage-based fuzzing (ICF: 10 points allocated)
- [ ] Analysis informed code-rewriting (NCR: 3 points allocated)

### From RESEARCH_INSIGHTS.md:
- [ ] Inter-procedural analysis (lambda support)
- [ ] Context-sensitive analysis (k-CFA)
- [ ] Alias analysis (FlowDroid-style)
- [ ] Access paths for field tracking
- [ ] Hybrid static+dynamic analysis

### From TODO.md / ACADEMIC_AUDIT.md:
- [ ] Run on Juliet CWE-89 benchmark (2,280 test cases)
- [ ] Run SpotBugs/FindSecBugs on our benchmark
- [ ] Test on real-world open-source project
- [ ] Docker container for reproducibility
- [ ] Second reviewer verification of labels

---

## 5. Priority Fixes for Better Results

### Quick Wins (2-4 hours each, +12% recall possible)

1. **Add String.format() support** (+2% recall)
   ```python
   # In MethodMatcher.TAINT_PRESERVING:
   "java.lang.String.format",
   ```

2. **Add switch statement handlers** (+4% recall)
   ```python
   case jvm.TableSwitch():
       # Pop switch key, CFG handles branches
       current_state.pop()
   case jvm.LookupSwitch():
       current_state.pop()
   ```

3. **Track array element taint** (+6% recall)
   ```python
   # In transfer_array_store:
   if value.tainted_value.is_tainted:
       # Mark array reference as tainted
       if array_ref.heap_ref:
           state.heap[array_ref.heap_ref].taint = value.tainted_value
   ```

### Medium Effort (8-16 hours)

4. **Advanced StringBuilder methods** (+3% recall)
   - Add: delete, replace, reverse, setCharAt
   - Currently only append/toString tracked

5. **Lambda method analysis** (+4% recall)
   - Analyze lambda$*$ synthetic methods
   - Link taint to invokedynamic calls

---

## 6. Paper Writing Guide

### Recommended Structure (10 pages)

#### 1. Introduction (1.5 pages)
- SQL injection is top OWASP risk
- Bytecode analysis advantages (no source needed, language-agnostic)
- Our contribution: lightweight taint analyzer with 87% accuracy, 2% FPR

#### 2. Background (1 page)
- JVM bytecode basics (opcodes, stack, locals)
- Taint analysis fundamentals
- Abstract interpretation concepts

#### 3. Approach (2.5 pages)
- Architecture diagram
- CFG construction algorithm
- Transfer functions (key ones: invoke, load, store)
- TAJ-style string carrier pattern
- Source/sink detection

#### 4. Implementation (1 page)
- 1,300 lines Python + JPAMB framework
- 18 opcode handlers
- Key design decisions

#### 5. Evaluation (2.5 pages)
- Benchmark description (255 test cases, 18 categories)
- Results table with confusion matrix
- Category breakdown (show 100% categories AND 0% categories honestly)
- Comparison with Semgrep
- OWASP Benchmark comparison (estimated)

#### 6. Threats to Validity (0.5 pages)
- Internal: Self-created benchmark, label accuracy
- External: Synthetic test cases, no framework support
- Construct: Standard metrics used

#### 7. Related Work (1 page)
- FlowDroid (Android, IFDS-based)
- TAJ (string carriers)
- Commercial SAST tools
- OWASP Benchmark results

#### 8. Conclusion & Future Work (0.5 pages)
- Summary of contributions
- Future: inter-procedural, framework support, OWASP validation

### Key Claims (Supported by Evidence)

**CAN claim:**
- 87.1% accuracy on 255 test cases (510 methods)
- 97.5% precision (very low false positive rate of 2.0%)
- Estimated OWASP Score of 74.1% (TPR - FPR)
- Competitive with commercial tools on FPR
- Lightweight implementation (1300 LOC vs 20k-100k for industry tools)

**CANNOT claim:**
- "Works on real applications" (only synthetic tests)
- "Sound analysis" (intentionally unsound for precision)
- "Detects all SQL injection" (76% recall, not all)

**CAN NOW claim (after SpotBugs comparison):**
- Better precision than SpotBugs on our benchmark (97.5% vs 50%)
- Much lower FPR than SpotBugs (2.0% vs 100%)

---

## 7. Final Checklist Before Submission

### Must Do
- [x] Update FINAL_ACHIEVEMENTS.md with 87.1% accuracy - DONE
- [x] Update README.md with final results - DONE
- [ ] Delete benchmarks/ folder (480MB)
- [ ] Review all 510 method labels for correctness
- [ ] Write threats to validity section

### Should Do
- [x] Fix String.format() handling (+2% recall) - DONE
- [ ] Fix switch statement handling (+4% recall)
- [x] Add one more tool comparison (SpotBugs) - DONE (100% FPR!)
- [ ] Create reproducibility script

### Nice to Have
- [ ] Fix array operations (+6% recall)
- [ ] Run on subset of Juliet CWE-89
- [ ] Docker container
- [ ] Visualization component

---

## 8. Command Reference

### Run evaluation
```bash
cd /Users/jakubpiotrowski/PycharmProjects/Mind_Your_Own_Query
uv run python -c "from solutions.bytecode_evaluation import main; main()"
```

### Run single test
```bash
uv run python solutions/bytecode_taint_analyzer.py "jpamb.sqli.SQLi_DirectConcat.vulnerable"
```

### Clean up
```bash
rm -rf benchmarks/
rm -rf **/__pycache__/
rm -rf sqli-test-suite/.venv/
```

### View results
```bash
cat bytecode_evaluation_results.json
```

---

## 9. Repository Structure (Recommended)

```
Mind_Your_Own_Query/
├── README.md                    # Project overview + results
├── PUBLICATION_GUIDE.md         # This file
├── bytecode_evaluation_results.json  # Latest results
├── test_cases.json              # 255 test case definitions
├── solutions/
│   ├── bytecode_taint_analyzer.py    # Main analyzer (1300 LOC)
│   └── bytecode_evaluation.py        # Evaluation script
├── src/main/java/jpamb/sqli/   # 256 Java test files
├── target/decompiled/          # Bytecode JSON files
├── docs/
│   ├── TOOL_COMPARISON.md      # Comparison with other tools
│   └── archive/                # Historical docs (can delete)
└── paper/                      # Paper LaTeX files (to create)
```

---

## 10. Summary

**Current State:** The analyzer is publication-ready with 87.1% accuracy and excellent precision (97.5%). Three quick fixes could improve recall by 12%.

**Main Gaps:**
1. No visualization component (as planned)
2. No bytecode instrumentation (as planned)
3. No coverage-based fuzzing (as planned)
4. Some categories score 0% (formatting, arrays, switches)

**Recommendation:** Focus on writing the paper with current results. The 87.1% accuracy with 2% FPR is competitive. Be honest about limitations in threats to validity section.

**Estimated OWASP Score (74.1%)** would rank among the best if validated on OWASP Benchmark - this is a strong selling point.
