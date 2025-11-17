# Mind Your Own Query: Static And Dynamic Analysis Approaches For SQL String Safety

**Authors:**
- Jakub Lukaszewski (s253077@dtu.dk)
- Jakub Piotrowski (s253074@dtu.dk)
- Landon Hassin (s252773@dtu.dk)
- Lawrence M. Ryan (s225243@dtu.dk)
- Matthew Asano (s225134@dtu.dk)

**Affiliation:** DTU Compute - Group 4, Kgs. Lyngby, Denmark

---

## Introduction

### Context

SQL injection (SQLi) consistently ranks among the most critical web application security risks, as highlighted by its persistent inclusion in the OWASP Top 10 list. This vulnerability class arises when an application constructs SQL queries by concatenating trusted strings with unsanitized user input. A malicious actor can provide specially formed input that alters the syntax of the SQL query, leading to data corruption, data breaches or system control loss. The fundamental challenge lies in accurately tracking and reasoning about how strings are constructed and manipulated throughout a program's execution. Performing this analysis at the Java bytecode level provides a language-agnostic approach that does not require source code, making it a versatile tool for security auditing.

### Gap

Currently, the JPAMB framework does not handle strings. In order to work with SQL injection detecting in program analysis, strings must be handled as a first-class data type. In modern applications, database queries are often assembled at runtime using string concatenation and user input, meaning that the ability to track and interpret string flows is essential for any meaningful security analysis. Listing 1 and Listing 2 illustrate the issue.

**Listing 1: Fixed SQL query (easily analyzable)**
```java
String query = "SELECT * FROM users WHERE id = 42";
```

**Listing 2: Dynamically constructed SQL query (hard to analyze)**
```java
String query = "SELECT * FROM users WHERE id = " + userInput;
```

Existing analyses struggle with the task of tracking dynamically constructed strings. Precise handling is complex, as real programs build queries through concatenations and substrings that most static tools cannot accurately model. Consequently, analyses either over-approximate taint flow, causing false positives or miss vulnerabilities due to under-approximation.

### Innovation

To solve this, we propose a positive taint analysis implemented as an abstract interpreter operating on Java bytecode. Our approach tracks taint at the **variable level** using boolean flags: each value is marked as either **TRUSTED** (from string literals or sanitized sources) or **UNTRUSTED** (from user input or external sources). While character-level bit-vector approaches offer finer granularity, our variable-level design provides several practical advantages: (1) simpler implementation that integrates seamlessly with existing abstract interpretation frameworks, (2) lower memory overhead suitable for analyzing large codebases, and (3) sufficient precision for detecting the SQL injection patterns found in real-world applications, where entire string variables (not individual characters) are typically concatenated into queries.

Our analysis defines precise transfer functions for Java bytecode string operations (e.g., STRING_CONCAT, SUBSTRING, REPLACE) that propagate taint conservatively: if any input to an operation is UNTRUSTED, the output is marked UNTRUSTED. This ensures soundness while maintaining practical precision. For example, concatenating a TRUSTED string literal with an UNTRUSTED input string produces an UNTRUSTED result, correctly flagging the potential vulnerability. The abstract interpreter operates on JVM bytecode, making it language-agnostic and suitable for analyzing compiled Java applications without requiring source code access.

A core component of our framework is the source and sink detection system. We identify UNTRUSTED sources (e.g., `HttpServletRequest.getParameter()`, `URLConnection.getInputStream()`) and dangerous sinks (e.g., `Statement.execute()`, `Statement.executeQuery()`). By tracking taint flow from sources through string operations to sinks, we can accurately detect unsafe SQL query construction. This approach directly addresses the 'explainability gap' in current automated security tools by providing clear taint flow paths that show exactly how untrusted data reaches SQL execution points.

### Evaluation

Our evaluation focuses on extending the JPAMB, which currently lacks string-handling benchmarks. We will develop a new test suite of approximately 25 small, targeted Java programs. These programs will model specific real-world SQLi scenarios, including both vulnerable string concatenations (as in Listing 2) and safe, parameterized queries. This extension will provide a controlled environment to test our variable-level taint analysis, establishing clear sources (e.g., `HttpServletRequest.getParameter()`, `URLConnection.getInputStream()`) and sinks (e.g., `Statement.execute()`, `Statement.executeQuery()`). These test cases will span varying complexity levels, from simple concatenations to nested operations involving substrings and control-flow variations, enabling us to precisely validate how taint propagates through string operations. Our analysis framework will automate the entire evaluation pipeline, interfacing directly with the JPAMB repository to execute test cases, collect outcomes, and compare our approach against baseline analyses, quantifying the precision improvements.

Our success criteria target measurable improvements that directly address the over- and under-approximation problems:

- **Technical:** detect 75% of SQL injection vulnerabilities in our extended JPAMB test suite.
- **Precision:** maintain a false positive rate below 30% (substantially better than the 40-60% common in typical SAST tools).
- **Performance:** analysis completion within 60 seconds per test case.
- **Academic:** produce a conference-quality 10-page paper suitable for workshop submission (e.g., SOAP @ PLDI, ISSTA Tool Demonstrations).

The tool will generate reports that show precisely how trusted values remain marked safe while untrusted values propagate to SQL execution points.

---

## Appendix

### Plan

In the contributions table below, the different tasks in the project are listed together with the corresponding contribution of each team member. The plan for implementing these things can be seen in the project plan (timeline). We plan to start with core implementations, those being extending the current benchmark suite and implementing the interpreter. We will then focus on extending functionalities with things such as handling novel data types and bytecode instrumentation. We will then refine everything through visualizations and optimizations. Finally, we will write the paper and prepare the presentation.

**Implementation:** we implement approximately 15 core string operations (concatenation, substring, replace, trim, case conversion) that account for 75% of SQL injection patterns. The team divides into four modules: (1) bytecode string analysis, (2) dynamic instrumentation, (3) false positive elimination, and (4) JPAMB test suite extension.

#### Project Timeline

The project spans from October 13, 2025 to December 15, 2025:

**Phase 1 (Oct 21 - Nov 15):**
- Literature Review (Oct 21 - Nov 5)
- Extend Benchmark Suite (Oct 21 - Nov 10)
- Implement Interpreter (Oct 30 - Nov 15)
- Implement Syntactic Analysis (Oct 30 - Nov 15)

**Phase 2 (Nov 11 - Nov 22):**
- Handle Novel Datatype (Nov 11 - Nov 22)
- Use Bytecode Instrumentation (Nov 11 - Nov 22)

**Phase 3 (Nov 16 - Nov 27):**
- Find Illustrating Examples (Nov 16 - Nov 27)
- Visualization of Analysis (Nov 16 - Nov 27)
- Optimize the Code (Nov 16 - Nov 27)

**Phase 4 (Nov 20 - Dec 10):**
- Write Paper (Nov 20 - Dec 1)
- Presentation Prep (Dec 2 - Dec 10)

**Key Milestones:**
- Proposal: November 1
- Paper: December 1
- Present: December 10

#### Contributions Table

Team members: S₁ = Jakub Lukaszewski (s253077), S₂ = Jakub Piotrowski (s253074), S₃ = Landon Hassin (s252773), S₄ = Lawrence M. Ryan (s225243), S₅ = Matthew Asano (s225134)

| ID  | Contribution | Points | S₁ | S₂ | S₃ | S₄ | S₅ |
|-----|--------------|--------|----|----|----|----|----|
| EXP | Extend Benchmark Suite | 5 | 3 | 0 | 2 | 0 | 0 |
| INN | Implement Interpreter | 10 | 5 | 3 | 2 | 0 | 0 |
| ISY | Implement Syntactic Analysis | 10 | 0 | 0 | 6 | 4 | 0 |
| NDT | Handle Novel Datatype | 10 | 5 | 5 | 0 | 0 | 0 |
| NIN | Use Bytecode Instrumentation | 8 | 0 | 0 | 0 | 8 | 0 |
| PEX | Find Illustrating Examples | 4 | 0 | 0 | 4 | 0 | 0 |
| PWP | Write Paper | 10 | 2 | 2 | 3 | 2 | 1 |
| VIS | Visualization of Analysis | 8 | 1 | 4 | 0 | 0 | 3 |
| EOP | Optimize the Code | 10 | 2 | 2 | 0 | 6 | 0 |
| NAN | Integrate Analyses | 5 | 0 | 0 | 0 | 2 | 3 |
| IBA | Implement Unbounded Static Analysis | 7 | 4 | 0 | 0 | 0 | 3 |
| NCR | Analysis informed code-rewriting | 3 | 0 | 1 | 0 | 0 | 2 |
| ICF | Implement Coverage-based Fuzzing | 10 | 0 | 0 | 0 | 0 | 10 |
| PRW | Read and Relate to Recent Papers | 10 | 0 | 5 | 5 | 0 | 0 |
| PMG | Project Management | 10 | 2 | 2 | 2 | 2 | 2 |
| **Total** | | **120** | **24** | **24** | **24** | **24** | **24** |
| **Suggested Max Grade** | | | **12** | **12** | **12** | **12** | **12** |

**Visualization:** the visualization component is the core for making our tool usable by developers who are not program analysis experts. Interactive visualization of taint flows from sources to sinks enables developers to quickly understand *where* the vulnerability originates. Research shows that visual debugging tools significantly reduce time-to-fix for security vulnerabilities. Our visualization will display variable-level taint propagation, showing exactly which string values in a constructed SQL query came from user input versus trusted sources. This addresses the "explainability gap" in automated security tools and facilitates developer adoption.

---

## References

- OWASP Top Ten
- Livshits, V. B., & Lam, M. S. (2005). SecuriBench Micro
- Boland, T., & Black, P. E. (2012). Juliet Test Suite
- Bermejo Higuera, J., et al. (2020). Benchmarking SAST tools
- Chin, E., & Wagner, D. (2009). Efficient character-level taint tracking
- Pauck, F., et al. (2018). Android visual debugging tools