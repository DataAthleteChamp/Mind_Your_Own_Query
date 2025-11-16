# TODO - Mind Your Own Query
**Project Deadline:** Dec 1, 2025 (Paper) | Dec 10, 2025 (Presentation)
**Last Updated:** November 16, 2025

---

## 🎯 Progress Overview

| Component | Status | Notes |
|-----------|--------|-------|
| Taint Module Implementation | ✅ **DONE** | All core classes implemented & tested |
| SQL Test Suite | ⏳ **PENDING MERGE** | Exists in `origin/feature/sqli-test-suite` |
| Taint Analyzer | ❌ **TODO** | Need to create in `solutions/` |
| Syntactic Baseline | ❌ **TODO** | Exists in remote branch, needs setup |
| Paper | ❌ **TODO** | Not started |
| Presentation | ❌ **TODO** | Not started |

---

## ✅ COMPLETED (Already Done!)

### Implementation
- [x] **Taint Module** (`jpamb/taint/`)
  - [x] `value.py` - TaintedValue class with trust tracking
  - [x] `transfer.py` - 7 transfer functions (concat, substring, replace, trim, split, join, case conversion)
  - [x] `sources.py` - SourceSinkDetector with HTTP, File, Network, System sources
  - [x] `README.md` - Complete documentation with examples
  - [x] 68 comprehensive tests covering all functionality

### Documentation
- [x] MASTER_PLAN.md - Detailed 15-day plan
- [x] GITFLOW.md - Git workflow rules
- [x] project_proposal.md - Academic proposal
- [x] README.md - Updated with project info

---

## 🔥 CRITICAL PATH (Must Do for Dec 1)

### Week 1: Integration & Testing (Nov 16-22)

#### 📍 IMMEDIATE (This Weekend - Nov 16-17)
- [ ] **1. Merge SQL Test Suite**
  ```bash
  git checkout main
  git pull origin main
  git merge origin/feature/sqli-test-suite
  git push origin main
  ```
  - [ ] Verify 25 test cases in `sqli-test-suite/` directory
  - [ ] Run baseline: `cd sqli-test-suite && python test_runner.py --analyzer my_analyzer.py`
  - [ ] Save baseline results to `baseline_results.json`

- [ ] **2. Merge Upstream Strings (Optional)**
  ```bash
  git fetch upstream
  git merge upstream/strings
  # Resolve conflicts in jpamb/jvm/base.py if needed
  git push origin main
  ```
  - [ ] Run health check: `uv run jpamb checkhealth`
  - [ ] Verify string tests pass

#### 📍 THIS WEEK (Nov 18-20)
- [ ] **3. Create Taint Analyzer** (`solutions/taint_analyzer.py`)
  - [ ] Import jpamb and taint modules
  - [ ] Use `jpamb.getcase()` to get method ID
  - [ ] Read source file with `jpamb.sourcefile()`
  - [ ] Parse method body (regex-based, keep it simple!)
  - [ ] Track taint through operations using TaintTransfer
  - [ ] Detect sources (getParameter, etc.) → mark as tainted
  - [ ] Detect sinks (execute, executeQuery) → check if tainted
  - [ ] Output: `sql injection;100%` or `ok;100%`

- [ ] **4. Test Taint Analyzer**
  - [ ] Run on 5 simple test cases manually
  - [ ] Run on full suite: `python test_runner.py --analyzer ../solutions/taint_analyzer.py`
  - [ ] Save results to `taint_results.json`
  - [ ] Calculate: detection rate, false positives, time

- [ ] **5. Compare Results**
  - [ ] Create `evaluation/compare.py` script
  - [ ] Compare syntactic vs taint results
  - [ ] Generate table for paper

#### 📍 END OF WEEK 1 (Nov 21-22)
- [ ] **6. Start Paper Outline**
  - [ ] Create `paper/` directory
  - [ ] Set up LaTeX or Overleaf
  - [ ] Outline 10 sections (Abstract → Conclusion)
  - [ ] Assign sections to team members

---

### Week 2: Paper Writing (Nov 23-29)

#### 📍 FIRST DRAFTS (Nov 23-25)
- [ ] **Each team member writes assigned section** (FIRST DRAFT)
  - [ ] Abstract (Jakub L.)
  - [ ] Introduction (Jakub L.)
  - [ ] Background (Landon)
  - [ ] Approach (Jakub P.)
  - [ ] Implementation (Jakub P.)
  - [ ] Test Suite (Landon)
  - [ ] Evaluation (Lawrence)
  - [ ] Results (Lawrence)
  - [ ] Discussion (Matthew)
  - [ ] Conclusion (Matthew)

#### 📍 FIGURES & TABLES (Nov 26-27)
- [ ] **Create All Figures**
  - [ ] Figure 1: System architecture
  - [ ] Figure 2: Example vulnerable code
  - [ ] Figure 3: Taint flow diagram
  - [ ] Figure 4: Performance comparison graph

- [ ] **Create All Tables**
  - [ ] Table 1: Test suite (25 cases, 5 categories)
  - [ ] Table 2: Results comparison (syntactic vs taint)
  - [ ] Table 3: Performance metrics
  - [ ] Table 4: Error analysis

#### 📍 INTEGRATION (Nov 28-29)
- [ ] Merge all sections into single paper
- [ ] Add all figures and tables
- [ ] Ensure consistent terminology
- [ ] Check narrative flow
- [ ] Add all citations

---

### Week 3: Finalization (Nov 30 - Dec 1)

#### 📍 FINAL POLISH (Nov 30)
- [ ] **Complete draft review**
  - [ ] Fill all [TODO] markers
  - [ ] Grammar & spell check
  - [ ] Verify all claims have evidence
  - [ ] Check page count (≤10 pages)
  - [ ] Format references properly

#### 📍 SUBMISSION DAY (Dec 1) 🎯
- [ ] **Final checks**
  - [ ] PDF generates correctly
  - [ ] All figures/tables appear
  - [ ] Author info complete
  - [ ] Abstract compelling

- [ ] **Create submission package**
  - [ ] `paper.pdf`
  - [ ] `source_code.zip` (jpamb/taint + solutions/)
  - [ ] `test_suite.zip` (25 Java test cases)
  - [ ] `results.zip` (evaluation data)
  - [ ] `README.txt` (how to reproduce)

- [ ] **SUBMIT** 🎉
  - [ ] Upload to submission system
  - [ ] Save confirmation
  - [ ] Tag repo: `git tag v1.0-submission`
  - [ ] Celebrate! 🍾

---

### Presentation Prep (Dec 2-10)

#### 📍 CREATE SLIDES (Dec 2-5)
- [ ] **20 slides** (Matthew leads, all contribute)
  - [ ] Title & motivation (2 slides)
  - [ ] Approach & implementation (4 slides)
  - [ ] Test suite & examples (3 slides)
  - [ ] Results & evaluation (4 slides)
  - [ ] Discussion & future work (2 slides)
  - [ ] Demo (2 slides)
  - [ ] Contributions & Q&A (3 slides)

- [ ] Create 2-3 min demo video

#### 📍 PRACTICE (Dec 6-8)
- [ ] Individual practice (Dec 6)
- [ ] Full team run-through #1 (Dec 6)
- [ ] Prepare Q&A answers (Dec 7)
- [ ] Full team run-through #2 (Dec 7)
- [ ] Final polish (Dec 8)

#### 📍 FINAL PREP (Dec 9)
- [ ] Test demo environment
- [ ] Save slides on USB
- [ ] Print notes (if needed)

#### 📍 PRESENTATION (Dec 10) 🎤
- [ ] Arrive early
- [ ] Set up and test
- [ ] **PRESENT** 🎉
- [ ] Answer questions
- [ ] Celebrate! 🍾🍾🍾

---

## 📊 Success Metrics

| Metric | Target | Current | Status |
|--------|--------|---------|--------|
| **Detection Rate** | ≥75% | TBD | ⏳ |
| **False Positives** | <30% | TBD | ⏳ |
| **Time per Test** | <60s | TBD | ⏳ |
| **Test Cases** | ≥20 | 25 | ✅ |
| **Paper Pages** | ~10 | 0 | ⏳ |
| **Presentation Slides** | 20 | 0 | ⏳ |

---

## 👥 Team Assignments

| Member | Week 1 | Week 2 | Week 3 |
|--------|--------|--------|--------|
| **Jakub L.** | Taint analyzer implementation | Abstract + Introduction | Presentation slides |
| **Jakub P.** | Merge branches, integration | Approach + Implementation | Demo video |
| **Landon** | Test suite setup, baseline | Background + Test Suite | Practice coordinator |
| **Lawrence** | Source/sink testing | Evaluation + Results | Q&A prep |
| **Matthew** | Visualization | Discussion + Conclusion | Presentation lead |

---

## 🚨 Blockers & Issues

| Date | Issue | Owner | Status | Resolution |
|------|-------|-------|--------|------------|
| Nov 16 | Need to merge SQL test suite | Jakub P. | ⏳ | Scheduled for this weekend |
| TBD | TBD | TBD | ⏳ | TBD |

---

## 📝 Quick Commands

### Run Tests
```bash
# Run taint module tests
pytest test/test_taint*.py -v

# Run SQL injection test suite (after merge)
cd sqli-test-suite
python test_runner.py --analyzer my_analyzer.py
```

### Health Checks
```bash
# JPAMB health check
uv run jpamb checkhealth

# Run string tests
uv run jpamb test --filter "Strings"
```

### Git Operations
```bash
# Merge SQL test suite
git merge origin/feature/sqli-test-suite

# Merge upstream strings
git fetch upstream
git merge upstream/strings

# Create feature branch
git checkout -b feature/my-feature

# Push your work
git push origin feature/my-feature
```

---

## 🎯 This Week's Focus (Nov 16-22)

**TOP PRIORITIES:**
1. ✅ Taint module done - great job!
2. 🔥 Merge SQL test suite (CRITICAL - do this weekend!)
3. 🔥 Create taint analyzer in solutions/
4. 🔥 Run full evaluation and get metrics
5. 🔥 Start paper outline

**GOAL:** By end of Week 1, have working analyzer + paper outline ready

---

## 📞 Need Help?

**Stuck on something?**
1. Check [MASTER_PLAN.md](MASTER_PLAN.md) for detailed instructions
2. Check [GITFLOW.md](GITFLOW.md) for git workflow
3. Ask in team chat
4. Daily standup: share blockers

---

**Remember:** You're ahead of schedule on implementation! The taint module is done and tested. Now focus on:
1. Merging the test suite
2. Creating the analyzer
3. Writing the paper

**You've got this! 🚀**

---

**Last Updated:** November 16, 2025
**Next Update:** Daily (update after each work session)
