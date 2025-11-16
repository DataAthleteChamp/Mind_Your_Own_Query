# Course Alignment Check
## 02242 Program Analysis - Project Requirements

**Last Updated:** November 16, 2025
**Course:** 02242 Program Analysis
**Instructor:** Christian Gram Kalhauge
**Team:** DTU Compute Group 4 (5 members)

---

## ✅ Requirements Summary

### 1. Proposal (Already Submitted? TBD)

**Required:**
- ~2 pages, ACM small format
- CGIE Model (Context, Gap, Innovation, Evaluation, Plan, Presentation)
- Grade 1-4, must score ≥12 points
- Technical Contributions table as appendix

**Your Status:**
- ✅ `project_proposal.md` exists (9927 bytes, detailed proposal)
- ✅ CGIE model covered:
  - ✅ Context: SQL injection as OWASP Top vulnerability
  - ✅ Gap: Current tools struggle with dynamic string construction
  - ✅ Innovation: Character-level (simplified to variable-level) taint analysis
  - ✅ Evaluation: 25 test cases, 75% detection, <30% FP, <60s per test
  - ✅ Plan: Timeline from Oct 21 - Dec 15
  - ✅ Presentation: Well-formatted
- ✅ Technical Contributions table included (120 points total)
- ⚠️ **ACTION NEEDED:** Verify if already submitted or needs submission

---

### 2. Paper (Due: December 1, 2025)

**Required Format:**
- **Max 10 pages** (excluding references)
- **ACM small format** (acmsmall mode)
- Must follow Simon Peyton Jones lecture advice

**Required Sections:**

#### Abstract
- [ ] Describing the paper
- **Your plan:** ✅ Assigned to Jakub Lukaszewski

#### Introduction (1-2 pages)
- [ ] Motivation and problem description (with examples)
- [ ] Research question
- [ ] Short description of solution
- [ ] List of contributions with forward references
- **Your plan:** ✅ Assigned to Jakub Lukaszewski

#### Example illustrating approach (1-2 pages)
- [ ] Concrete example showing your approach
- **Your plan:** ✅ Part of approach section

#### Approach and Theory (2-3 pages)
- [ ] Formal description of the approach
- [ ] Walkthrough of theory needed
- [ ] Theoretical guarantees
- **Your plan:** ✅ Assigned to Jakub Piotrowski

#### Evaluation (2-3 pages) **CRITICAL**
- [ ] **Empirical evaluation of approach**
- [ ] **Compared against at least ONE other technique** ⚠️
- [ ] Analysis of results
- [ ] Discussion of threats to validity
- **Your plan:** ✅ Assigned to Lawrence Ryan
- **Your approach:** Compare syntactic vs taint analyzer ✅

#### Related Work (1-2 pages)
- [ ] Discussion of technique and alternatives
- [ ] Explanation why other techniques from lectures weren't used
- **Your plan:** ✅ Part of Background (Landon) + Discussion (Matthew)

#### Conclusion (0-1/2 page)
- [ ] Short recap of paper
- **Your plan:** ✅ Assigned to Matthew Asano

**Your Status:**
- ❌ Paper not started
- ✅ Clear section assignments
- ✅ Outline planned
- ⚠️ **CRITICAL:** Must compare against at least one other technique
  - ✅ You're doing this: Syntactic baseline vs Taint analyzer

---

### 3. Project Overview Sheet

**Required:**
- Single A4 page
- Name, student number, feedback group, images of each student
- **Technical Contributions table** summarizing each member's work

**Your Status:**
- ❌ Not created yet
- ✅ Technical Contributions planned in `project_proposal.md`
- ⚠️ **ACTION NEEDED:** Create before final submission

---

### 4. Video Presentation (Due: Day before first exam)

**Required:**
- **Max 5 minutes**
- Highlight the project
- Help start conversation

**Your Status:**
- ❌ Not created
- ✅ Planned for Dec 2-5
- ✅ Assigned to Matthew (lead)

---

### 5. Oral Defence (~30 min per group)

**Format:**
- Start with 5-min video
- Individual questioning
- Questions on technical contributions + course material

**Your Status:**
- ⏳ Scheduled for Dec 10
- ✅ Preparation planned

---

## 📊 Technical Contributions Analysis

### From Course Requirements

**Grading Scale (Group of 5):**
- Grade 12: ≥20 points across 5 contributions
- Grade 10: ≥15 points across 4 contributions
- Grade 7: ≥10 points across 3 contributions
- Grade 4: ≥7 points across 3 contributions
- Grade 02: ≥5 points across 3 contributions

### Your Planned Contributions (from project_proposal.md)

| ID | Contribution | Max Points | Course Max | Status | Notes |
|----|--------------|------------|------------|--------|-------|
| **EXP** | Extend Benchmark Suite | 5 | 5 | ✅ DONE | 25 SQL injection test cases = 12.5 points (0.5 per method) - **EXCEEDS MAX!** |
| **INN** | Implement Interpreter | 10 | 10 | ⚠️ PARTIAL | Need to create taint analyzer |
| **ISY** | Implement Syntactic Analysis | 10 | 10 | ⚠️ EXISTS | In remote branch, needs integration |
| **NDT** | Handle Novel Datatype (Strings) | 10 | 10 | ✅ DONE | Taint module fully implemented! |
| **NIN** | Use Bytecode Instrumentation | 8 | 10 | ❌ TODO | Planned but not started |
| **PEX** | Find Illustrating Examples | 4 | 4 | ❌ TODO | Need 2 examples (2 pts each) |
| **PWP** | Write Paper | 10 | 10 | ❌ TODO | 10 pages = 10 points |
| **VIS** | Visualization of Analysis | 8 | N/A | ❌ TODO | Not in official list, but good for presentation |
| **EOP** | Optimize the Code | 10 | 10 | ❌ TODO | 5 pts per order of magnitude |
| **NAN** | Integrate Analyses | 5 | 15 | ⚠️ PARTIAL | Syntactic + Taint = 5 pts (one after first) |
| **IBA** | Implement Unbounded Static Analysis | 7 | 7 | ❌ TODO | Run to fixed point |
| **NCR** | Analysis informed code-rewriting | 3 | 10 | ❌ TODO | Optional |
| **ICF** | Implement Coverage-based Fuzzing | 10 | 10 | ❌ TODO | Optional (stretch) |
| **PRW** | Read and Relate to Recent Papers | 10 | 10 | ❌ TODO | 1 pt per paper, need 10 papers |
| **PMG** | Project Management | 10 | 9 | ✅ ONGOING | 5 people = 6 pts (3 per person over 3) |

### Realistic Points Calculation (What You Can Achieve)

| Contribution | Realistic Points | Rationale |
|--------------|------------------|-----------|
| **EXP** - Extend Benchmark Suite | **5** | Max is 5, even though you have 25 cases |
| **NDT** - Handle Novel Datatype | **10** | ✅ Strings fully implemented (taint module) |
| **ISY** - Implement Syntactic Analysis | **10** | ✅ Exists in remote branch |
| **IIN** - Implement Interpreter | **10** | ✅ Taint analyzer (simplified interpreter) |
| **NAN** - Integrate Analyses | **5** | Syntactic + Taint comparison |
| **PWP** - Write Paper | **10** | 10 pages = 10 points |
| **PEX** - Find Illustrating Examples | **4** | 2 examples planned |
| **PRW** - Read & Relate Papers | **10** | Need to read ~10 papers |
| **PMG** - Project Management | **6** | 5 people (3 over base of 3) |
| **PDI** - Process Diagram | **3** | Easy to add (system architecture) |
| **TOTAL REALISTIC** | **73** | Strong for grade 12 |

### Per-Student Calculation (Example)

For each student to get Grade 12, need ≥20 points across ≥5 contributions:

**Example Student (Jakub L.):**
- NDT: 5 points (taint implementation lead)
- IIN: 5 points (taint analyzer)
- ISY: 6 points (syntactic analysis support)
- PWP: 2 points (abstract + intro)
- PRW: 5 points (5 papers)
- **Total: 23 points across 5 contributions** → **Grade 12 ✅**

**⚠️ IMPORTANT:** Each student needs to document their specific contributions in the Project Overview Sheet.

---

## 🎯 Alignment with Course Project Ideas

### Your Project vs. "Handling String" Example

**From Course (Page 3):**
> (Ctx) Strings are one of the basic units of computing. (Gap) However, currently none of the techniques shown in class handle strings. (Inn) In this project, we extend our current analyses to handle strings. (Eval) To evaluate our implementation we will expand the JPAMB suite to contain cases that show normal use cases of strings.

**Your Project:**
- ✅ Context: SQL injection (string-based vulnerability)
- ✅ Gap: Tools struggle with dynamic string construction
- ✅ Innovation: Taint analysis for strings
- ✅ Evaluation: 25 SQL injection test cases

**Suggested Max Contributions (Course Example):**
- Groups of 5: Grade 7

**Your Contributions:**
- More comprehensive than course example
- Additional analyses (syntactic + taint comparison)
- More test cases (25 vs typical 10)
- **Expected Grade: 10-12** ✅

---

## ✅ Requirements Checklist

### Deliverables

#### Before Submission (Dec 1)
- [ ] **Paper** (10 pages, ACM format)
  - [ ] Abstract
  - [ ] Introduction (1-2 pages)
  - [ ] Example (1-2 pages)
  - [ ] Approach & Theory (2-3 pages)
  - [ ] Evaluation (2-3 pages) - **WITH COMPARISON**
  - [ ] Related Work (1-2 pages)
  - [ ] Conclusion (0.5 pages)
  - [ ] References

- [ ] **Project Overview Sheet** (1 page A4)
  - [ ] Names, student numbers, feedback group
  - [ ] Student photos
  - [ ] Technical Contributions table (individual breakdown)
  - [ ] Suggested maximal grade per student

- [ ] **Code Submission**
  - [ ] Source code (`jpamb/taint/`, `solutions/`)
  - [ ] Test suite (25 cases)
  - [ ] Results (evaluation data)
  - [ ] README (reproduction instructions)

#### Before Exam (Dec 10)
- [ ] **Video Presentation** (max 5 min)
  - [ ] Highlights of project
  - [ ] Demo
  - [ ] Clear and engaging

- [ ] **Presentation Slides**
  - [ ] Ready for 30-min oral defence
  - [ ] Questions preparation

---

## 🚨 Critical Issues & Recommendations

### ✅ GOOD NEWS

1. **Strong Technical Foundation**
   - ✅ Taint module fully implemented
   - ✅ 25 test cases (exceeds typical requirements)
   - ✅ Two analysis approaches (syntactic + taint)
   - ✅ Clear comparison possible

2. **Well Above Minimum**
   - Minimum for Grade 10 (group of 5): ≥15 points
   - Your realistic total: ~73 points
   - Per student: ~20+ points achievable

3. **Aligned with Course Examples**
   - Similar to "Handling String" project idea
   - More comprehensive evaluation

### ⚠️ MUST FIX

1. **Paper Comparison Requirement** (CRITICAL)
   - ✅ You're already planning this: Syntactic vs Taint
   - ❌ **MUST** have comparison in evaluation section
   - ✅ Your plan includes baseline comparison - good!

2. **Paper Not Started** (11 days until Dec 1)
   - ⏰ Need to start IMMEDIATELY
   - ✅ Sections assigned
   - ⚠️ Risk: Paper quality suffers if rushed

3. **Technical Contributions Documentation**
   - ⚠️ Need Project Overview Sheet
   - ⚠️ Each student must document specific contributions
   - ⚠️ Track who did what (for individual grading)

### 📋 Recommendations

#### IMMEDIATE (This Weekend - Nov 16-17)

1. **Verify Proposal Submission**
   - Check if `project_proposal.md` was officially submitted
   - If not, format as ACM small and submit ASAP

2. **Merge Test Suite** (Highest Priority)
   ```bash
   git merge origin/feature/sqli-test-suite
   ```

3. **Start Paper Outline**
   - Create LaTeX template (ACM small format)
   - Set up Overleaf for collaboration
   - Create section stubs

#### THIS WEEK (Nov 18-22)

4. **Create Taint Analyzer**
   - Implement `solutions/taint_analyzer.py`
   - Test on full suite
   - Get baseline metrics

5. **Run Comparison**
   - Syntactic vs Taint results
   - Generate comparison tables
   - **THIS IS REQUIRED FOR PAPER**

6. **Start Writing**
   - Each person writes their assigned section
   - Don't wait for perfect code

#### NEXT WEEK (Nov 23-29)

7. **Complete Paper Draft**
   - All sections written
   - Figures and tables added
   - Comparison analysis included

8. **Create Project Overview Sheet**
   - Document each student's contributions
   - Calculate individual points
   - Add photos and info

9. **Prepare Submission Package**
   - Code archive
   - Test suite archive
   - Results archive
   - README

---

## 📊 Grade Projection

### Current Status

**Completed Contributions:**
- NDT (Handle Novel Datatype): 10 points
- EXP (Extend Benchmark Suite): 5 points
- PMG (Project Management): 6 points
- **Subtotal:** 21 points

**In Progress:**
- ISY (Syntactic Analysis): 10 points (exists in branch)
- IIN (Implement Interpreter/Analyzer): 10 points (taint analyzer)
- NAN (Integrate Analyses): 5 points (comparison)
- **Subtotal:** 25 points

**TODO (Realistic):**
- PWP (Write Paper): 10 points
- PRW (Read Papers): 10 points
- PEX (Illustrating Examples): 4 points
- PDI (Process Diagram): 3 points
- **Subtotal:** 27 points

**TOTAL PROJECTED:** 73 points

### Individual Grade Projection (Example)

Assuming even distribution with specialization:

**Per Student (Group of 5):**
- Average: 73 / 5 = 14.6 points per person
- With proper distribution: 15-23 points per person
- Across 4-5 different contributions each

**Expected Grades:**
- With good paper (10 pts) + current work: **Grade 10-11** ✅
- With excellent execution: **Grade 12** ✅

---

## 🎯 Success Criteria

### Minimum for Grade 10 (Group of 5)
- ≥15 points per student
- Across ≥4 contributions
- **Status:** ✅ On track

### Target for Grade 12 (Group of 5)
- ≥20 points per student
- Across ≥5 contributions
- **Status:** ✅ Achievable with current plan

### Requirements for All Grades
- ✅ Paper well-written (10 pages)
- ✅ Comparison with other technique (syntactic vs taint)
- ✅ Claims supported by evaluation
- ✅ Use of course content demonstrated
- ✅ Problem is interesting (SQL injection ✅)
- ✅ Solution is innovative (taint analysis ✅)

---

## 📝 Action Items Summary

### CRITICAL (This Weekend)
1. [ ] Verify proposal was submitted
2. [ ] Merge SQL test suite branch
3. [ ] Set up paper template (ACM small, Overleaf)
4. [ ] Create paper outline with section assignments

### HIGH PRIORITY (This Week)
5. [ ] Implement taint analyzer (`solutions/taint_analyzer.py`)
6. [ ] Run full evaluation (syntactic vs taint)
7. [ ] Generate comparison tables and figures
8. [ ] Each person starts writing their assigned section

### BEFORE DEC 1
9. [ ] Complete paper (10 pages)
10. [ ] Create Project Overview Sheet
11. [ ] Prepare code submission package
12. [ ] Final review and submission

### BEFORE DEC 10
13. [ ] Create 5-min video presentation
14. [ ] Prepare oral defence slides
15. [ ] Practice presentation
16. [ ] Review course questions

---

## 📚 References from Course

**Paper Format:**
- ACM small format: https://www.acm.org/publications/proceedings-template
- Simon Peyton Jones lecture on writing: (linked in course)

**Grading:**
- Based on learning objectives
- Technical contributions (use of course content)
- Project quality (readable, warranted, supported by evaluation)
- Innovation (interesting problem, innovative solution)

**Contact:**
- Instructor: Christian Gram Kalhauge (chrg@dtu.dk)

---

**CONCLUSION: Your project is well-aligned with course requirements and on track for Grade 10-12. The main priority is completing the paper with proper comparison and documenting individual contributions.**

**You're in excellent shape! Just execute the plan. 🚀**

---

**Last Updated:** November 16, 2025
**Next Review:** After paper first draft (Nov 25)
