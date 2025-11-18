# Markdown Files - Keep or Archive?

**Last Updated:** Nov 17, 2025
**Purpose:** Decision guide for commit cleanup

---

## ✅ KEEP - Essential for Work (7 files)

| File | Purpose | Why Keep |
|------|---------|----------|
| **README.md** | Project setup & quick start | First file anyone reads |
| **TODO.md** | Current status & next steps | Daily work tracking |
| **FINAL_ACHIEVEMENTS.md** | Official results (88%) | Paper results reference |
| **PAPER_WRITING_GUIDE.md** | Paper writing instructions | Dec 1 deadline critical |
| **RESEARCH_INSIGHTS.md** | Research background | Related Work section |
| **jpamb/taint/README.md** | Taint API documentation | Code reference |
| **sqli-test-suite/README.md** | Test suite guide | Running tests |

---

## ✅ KEEP - Needed for Submission (3 files)

| File | Purpose | Why Keep |
|------|---------|----------|
| **COURSE_ALIGNMENT.md** | Course requirements checklist | Prove we meet all criteria |
| **RESEARCH_COMPARISON.md** | vs FlowDroid, TAJ, etc. | Competitive analysis for paper |
| **project_proposal.md** | Original proposal | Show baseline vs achievement |

---

## 📚 KEEP - Reference (5 files)

| File | Purpose | Keep? |
|------|---------|-------|
| **GITFLOW.md** | Git workflow | ✅ Useful for team |
| **OPCODES.md** | JVM opcode stats | ✅ Technical reference |
| **CONTRIBUTING.md** | Contribution guide | ✅ Standard practice |
| **CHANGELOG.md** | Version history | ✅ Standard practice |

---

## 🗑️ ARCHIVE - Not Needed for Daily Work

**Already archived in docs/archive/:**
- BYTECODE_EVALUATION_SUMMARY.md (duplicate of FINAL_ACHIEVEMENTS)
- IMPLEMENTATION_STRATEGY.md (outdated planning)
- IMPROVEMENTS.md (redundant with TODO)
- COMPREHENSIVE_QUALITY_REPORT.md (reference only)
- IMPROVEMENTS_SUMMARY.md (historical)
- CODE_QUALITY_CHECK.md (quality report)
- RECOMMENDED_TEST_CASES.md (future work)
- FUTURE_IMPROVEMENTS.md (future work)

**Can archive now:**
- DOCS_CLEANUP_SUMMARY.md (meta doc about cleanup - not needed after commit)

---

## 📊 Summary

| Category | Count | Action |
|----------|-------|--------|
| Essential for work | 7 | ✅ Keep in root |
| Needed for submission | 3 | ✅ Keep in root |
| Reference/Boilerplate | 4 | ✅ Keep in root |
| Already archived | 8 | 📦 In docs/archive/ |
| To archive | 1 | 🗑️ Move to archive |

**Total MD files in root after cleanup:** 14 (down from 20)

---

## 🎯 Recommendation

**Keep these 14 files in root:**
1. README.md
2. TODO.md
3. FINAL_ACHIEVEMENTS.md
4. PAPER_WRITING_GUIDE.md
5. RESEARCH_INSIGHTS.md
6. COURSE_ALIGNMENT.md
7. RESEARCH_COMPARISON.md
8. project_proposal.md
9. GITFLOW.md
10. OPCODES.md
11. CONTRIBUTING.md
12. CHANGELOG.md
13. jpamb/taint/README.md
14. sqli-test-suite/README.md

**Archive:**
- DOCS_CLEANUP_SUMMARY.md → docs/archive/

**Result:** Clean, focused documentation with everything needed for paper + submission
