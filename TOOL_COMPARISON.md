# SQL Injection Detection Tool Comparison

## Summary

This document compares our bytecode taint analyzer against industry tools on two benchmarks:
1. **Our Benchmark** (MYOQ): 255 test cases (510 methods: 255 vulnerable + 255 safe)
2. **OWASP Benchmark v1.2**: 504 SQL injection test cases (272 vulnerable + 232 safe)

---

## Results on Our Benchmark (MYOQ - 255 Test Cases)

| Tool | Accuracy | Precision | Recall (TPR) | F1 Score | FPR |
|------|----------|-----------|--------------|----------|-----|
| **Our Analyzer** | **87.1%** | **97.5%** | **76.1%** | **85.5%** | **2.0%** |
| SpotBugs + FindSecBugs | 50.0% | 50.0% | 100.0% | 66.7% | 100.0% |
| Semgrep | 50.0% | 50.0% | 60.0% | 54.5% | 60.0% |

### Confusion Matrix - Our Analyzer
| | Predicted Vulnerable | Predicted Safe |
|---|---------------------|----------------|
| **Actually Vulnerable** | TP=194 | FN=61 |
| **Actually Safe** | FP=5 | TN=250 |

### Confusion Matrix - SpotBugs + FindSecBugs
| | Predicted Vulnerable | Predicted Safe |
|---|---------------------|----------------|
| **Actually Vulnerable** | TP=255 | FN=0 |
| **Actually Safe** | FP=255 | TN=0 |

*Note: SpotBugs flags ANY non-constant string passed to executeQuery as vulnerable, regardless of source.*

### Confusion Matrix - Semgrep
| | Predicted Vulnerable | Predicted Safe |
|---|---------------------|----------------|
| **Actually Vulnerable** | TP=153 | FN=102 |
| **Actually Safe** | FP=153 | TN=102 |

*Note: Semgrep operates at file-level, flagging entire files as vulnerable/safe, not individual methods.*

---

## Official OWASP Benchmark v1.2 Results (SQL Injection - 504 Test Cases)

| Tool | TPR (Recall) | FPR | OWASP Score |
|------|-------------|-----|-------------|
| FBwFindSecBugs v1.4.6 | 100.0% | 90.5% | 9.5% |
| FBwFindSecBugs v1.4.0 | 53.7% | 55.6% | -1.9% |
| FindBugs v3.0.1 | 53.7% | 55.6% | -1.9% |
| OWASP ZAP vD-2016-09-05 (DAST) | 58.1% | 1.3% | 56.8% |
| PMD v5.2.3 | 0.0% | 0.0% | 0.0% |
| SonarQube Java Plugin v3.14 | 0.0% | 0.0% | 0.0% |

### Commercial Tools (Anonymous, OWASP Benchmark v1.1)
| Tool | TPR (Recall) | FPR | OWASP Score |
|------|-------------|-----|-------------|
| SAST-01 | 36.6% | 12.9% | 23.7% |
| SAST-02 | 94.0% | 61.8% | 32.3% |
| SAST-03 | 82.0% | 47.0% | 35.0% |
| SAST-04 | 82.5% | 50.7% | 31.9% |
| SAST-05 | 77.0% | 61.8% | 15.2% |
| SAST-06 | 100.0% | 90.2% | 9.8% |

*OWASP Score = TPR - FPR (higher is better, max 100%)*

---

## Comparative Analysis

### Our Analyzer Strengths
1. **Low False Positive Rate (2.0%)** - Far better than most tools tested on OWASP:
   - vs. FBwFindSecBugs (90.5% FPR)
   - vs. FindBugs (55.6% FPR)
   - vs. Commercial SAST tools (avg ~50% FPR)

2. **High Precision (97.5%)** - When it flags something, it's almost always correct

3. **Balanced Performance** - Good recall (76.1%) with minimal false positives

### OWASP Score Comparison (Estimated)
If our analyzer achieved similar results on OWASP Benchmark:
- **Our Analyzer (estimated)**: TPR 76.1% - FPR 2.0% = **74.1% OWASP Score**
- Best free tool (OWASP ZAP): 56.8%
- Best open-source SAST: 9.5% (FBwFindSecBugs)

### Known Limitations (from Category Analysis)
Our analyzer currently scores 0% detection on:
- String formatting (`String.format()`) - 5 test cases
- Array operations - 15 test cases
- Switch statements - 10 test cases

Fixing these would improve recall from 76.1% to ~88%.

---

## Category Breakdown - Our Benchmark

| Category | Vuln Detected | Vuln Total | Safe OK | Safe Total | Detection Rate |
|----------|--------------|------------|---------|------------|----------------|
| basic_concatenation | 5 | 5 | 4 | 5 | 100% |
| string_operations | 5 | 5 | 5 | 5 | 100% |
| control_flow | 17 | 20 | 20 | 20 | 85% |
| stringbuilder | 3 | 3 | 3 | 3 | 100% |
| real_world | 7 | 7 | 6 | 7 | 100% |
| concatenation | 20 | 20 | 20 | 20 | 100% |
| string_ops | 30 | 30 | 30 | 30 | 100% |
| string_builder | 15 | 15 | 15 | 15 | 100% |
| loops | 15 | 15 | 15 | 15 | 100% |
| **formatting** | **0** | **5** | 5 | 5 | **0%** |
| advanced | 18 | 30 | 27 | 30 | 60% |
| **advanced_stringbuilder** | 4 | 20 | 20 | 20 | 20% |
| method_chaining | 20 | 20 | 20 | 20 | 100% |
| nested_loops | 15 | 15 | 15 | 15 | 100% |
| **array_operations** | **0** | **15** | 15 | 15 | **0%** |
| conditional_assignment | 10 | 10 | 10 | 10 | 100% |
| **switch_statements** | **0** | **10** | 10 | 10 | **0%** |
| while_loops | 10 | 10 | 10 | 10 | 100% |

---

## Conclusions

1. **Our bytecode taint analyzer achieves competitive performance** with 87.1% accuracy and significantly lower false positive rates than industry tools.

2. **The precision-recall tradeoff is favorable**: 97.5% precision means developers won't waste time on false alarms.

3. **Estimated OWASP Score of 74.1%** would rank among the best available tools if validated.

4. **Three specific improvements** (formatting, arrays, switches) could improve recall by ~12%.

---

## Data Sources

- Our Benchmark: `bytecode_evaluation_results.json` (this project)
- OWASP Benchmark: `benchmarks/BenchmarkJava-official/scorecard/` (official results)
- Semgrep: Run via `semgrep --config=p/java` on our benchmark
