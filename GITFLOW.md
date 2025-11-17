# Git Flow Rules
## Mind Your Own Query - Development Workflow

**Last Updated:** November 16, 2025

---

## Terminology

### A) Origin Repo
**Our repository** - A fork of Professor's repo
- **URL:** `https://github.com/DataAthleteChamp/Mind_Your_Own_Query.git`
- **Remote name:** `origin`
- **Access:** Full read/write (our team's workspace)

### B) Upstream Repo
**Professor's repository** - The original JPAMB repo from which we forked
- **URL:** `https://github.com/kalhauge/jpamb.git`
- **Remote name:** `upstream`
- **Access:** Read-only (reference and sync source)

---

## Branches of Origin

### 1. `main` Branch
- **Purpose:** Mirrors upstream's repo main branch
- **Stability:** Must always be stable and deployable
- **Protection:** NEVER commit directly to main
- **Updates:** Only updated by merging approved Pull Requests (PRs)

### 2. Feature Branches
- **Naming:** `feature/brief-description`
- **Examples:**
  - `feature/sqli-test-suite`
  - `feature/taint-tracking`
  - `feature/visualization`
  - `feature/paper-figures`
- **Lifespan:** Created for specific work, deleted after merge
- **Scope:** One feature/fix/task per branch

---

## Git Flow Workflow

### Step 1: Setup - The Main Branch

**Before starting any work:**

```bash
# 1. Ensure you're on main
git checkout main

# 2. Sync with upstream (Professor's repo)
git fetch upstream
git merge upstream/main

# 3. Push updates to our fork
git push origin main
```

**Rules:**
- ✅ Main branch must always be stable and deployable
- ❌ NEVER commit directly to the main branch
- ✅ Main is updated only by merging approved Pull Requests (PRs)
- ✅ Sync with upstream regularly (at least weekly, or before starting new features)

---

### Step 2: Start Work

**Create a new branch for your feature/fix:**

```bash
# 1. Ensure you start from the latest stable code
git checkout main

# 2. Pull the absolute latest changes into your local main
git pull origin main

# 3. Create and switch to a new, descriptively named branch
git checkout -b feature/brief-description
```

**Branch Naming Convention:**

| Type | Prefix | Example |
|------|--------|---------|
| New Feature | `feature/` | `feature/taint-tracking` |
| Bug Fix | `fix/` | `fix/false-positive-builder` |
| Documentation | `docs/` | `docs/api-documentation` |
| Testing | `test/` | `test/integration-tests` |
| Refactoring | `refactor/` | `refactor/simplify-parser` |
| Experimental | `experiment/` | `experiment/character-level` |

**Examples:**
```bash
git checkout -b feature/taint-value-class
git checkout -b fix/string-concat-bug
git checkout -b docs/setup-instructions
git checkout -b test/taint-transfer-tests
```

---

### Step 3: Develop

**Work on your new branch and commit frequently:**

#### Commit Atomically
Each commit should represent a single, logical change.

#### Write Clear Messages
Use descriptive prefixes to clarify the commit's intent.

**Commit Message Format:**
```
<TYPE>: <Short description (50 chars max)>

<Optional detailed explanation (wrap at 72 chars)>

<Optional references to issues/tasks>
```

**Commit Types:**

| Type | When to Use | Example |
|------|-------------|---------|
| `FEAT:` | New feature or functionality | `FEAT: Add TaintedValue class` |
| `FIX:` | Bug fix | `FIX: Correct substring taint propagation` |
| `DOCS:` | Documentation changes | `DOCS: Update README with setup steps` |
| `TEST:` | Adding or updating tests | `TEST: Add unit tests for concat operation` |
| `REFACTOR:` | Code refactoring (no behavior change) | `REFACTOR: Simplify transfer function logic` |
| `CHORE:` | Maintenance tasks | `CHORE: Update dependencies` |
| `STYLE:` | Code formatting, whitespace | `STYLE: Apply black formatter` |
| `PERF:` | Performance improvements | `PERF: Optimize taint propagation` |

**Commit Workflow:**
```bash
# 1. Stage your changes
git add .
# OR stage specific files
git add jpamb/taint/value.py test/test_taint_value.py

# 2. Commit with clear message
git commit -m "FEAT: Add user authentication endpoint"

# 3. Repeat as you work
# Make small, frequent commits!
```

**Good Commit Examples:**
```bash
git commit -m "FEAT: Implement TaintedValue class with trust tracking"
git commit -m "TEST: Add unit tests for string concatenation"
git commit -m "FIX: Correct false positive in StringBuilder detection"
git commit -m "DOCS: Add docstrings to transfer functions"
git commit -m "REFACTOR: Extract source detection into separate module"
```

**Bad Commit Examples:**
```bash
git commit -m "fixes"  # ❌ Too vague
git commit -m "WIP"    # ❌ Not descriptive
git commit -m "stuff"  # ❌ Meaningless
git commit -m "asdf"   # ❌ No information
```

---

### Step 4: Share Your Work

**Push your changes when you need to:**
- Share your progress with the team
- Back up your work to GitHub
- Prepare for code review

```bash
# Push to your feature branch
git push origin feature/brief-description

# First time pushing a new branch, use -u to set upstream
git push -u origin feature/brief-description
```

**When to push:**
- ✅ End of each work session
- ✅ Before requesting code review
- ✅ When you need team feedback
- ✅ At least daily (for backup)

---

### Step 5: Prepare for Review

**Before creating a Pull Request, ensure your branch is up-to-date and clean:**

```bash
# 1. Switch to main branch
git checkout main

# 2. Sync your local main with the latest remote changes
git pull origin main

# 3. Optionally: Sync with upstream (Professor's repo)
git fetch upstream
git merge upstream/main
git push origin main

# 4. Go back to your feature branch
git checkout feature/brief-description

# 5. Merge main into your branch (or rebase for cleaner history)
git merge main
# OR for linear history:
# git rebase main

# 6. Resolve any conflicts if they occur
# ... fix conflicts ...
# git add <conflicted-files>
# git commit  (if merge)
# git rebase --continue  (if rebase)

# 7. Push updated branch
git push origin feature/brief-description
# If you rebased, may need force push:
# git push -f origin feature/brief-description
```

**Pre-PR Checklist:**
- [ ] Code is working and tested
- [ ] All tests pass locally
- [ ] Branch is up-to-date with main
- [ ] Conflicts are resolved
- [ ] Commits are clean and descriptive
- [ ] Code follows project style guidelines
- [ ] Documentation is updated if needed

---

### Step 6: Submit Pull Request

**Create a Pull Request on GitHub:**

1. **Go to GitHub:**
   - Navigate to `https://github.com/DataAthleteChamp/Mind_Your_Own_Query`
   - Click "Pull Requests" tab
   - Click "New Pull Request"

2. **Configure PR:**
   - **Base branch:** `main` (target)
   - **Compare branch:** `feature/brief-description` (your work)
   - Ensure the PR is merging FROM your feature branch INTO the main branch

3. **Write PR Description:**
   ```markdown
   ## Description
   Brief summary of what this PR does

   ## Changes
   - Added TaintedValue class
   - Implemented transfer functions for concat, substring
   - Added 15 unit tests

   ## Testing
   - All unit tests pass
   - Tested on 25 SQL injection cases
   - Performance: <0.5s per test

   ## Checklist
   - [x] Code is tested
   - [x] Documentation updated
   - [x] No breaking changes
   - [x] Follows coding standards
   ```

4. **Request Review:**
   - Assign at least one reviewer from the team
   - Add relevant labels (feature, bug, documentation, etc.)
   - Link to related issues or tasks

5. **Address Feedback:**
   - Respond to comments
   - Make requested changes
   - Push additional commits to the same branch
   - Request re-review when ready

6. **Merge:**
   - Once approved, reviewer or author can merge
   - Use "Squash and Merge" for clean history (optional)
   - Delete feature branch after merge

---

## Step 7: After Merge - Cleanup

**Clean up after your PR is merged:**

```bash
# 1. Switch to main
git checkout main

# 2. Pull the merged changes
git pull origin main

# 3. Delete local feature branch
git branch -d feature/brief-description

# 4. Delete remote feature branch (if not done via GitHub)
git push origin --delete feature/brief-description

# 5. Verify branches are cleaned up
git branch -a
```

---

## Quick Reference Commands

### Daily Workflow
```bash
# Morning: Start new feature
git checkout main
git pull origin main
git checkout -b feature/my-new-feature

# During day: Work and commit
git add .
git commit -m "FEAT: Add new functionality"
git push origin feature/my-new-feature

# Evening: Update from main if needed
git checkout main
git pull origin main
git checkout feature/my-new-feature
git merge main
git push origin feature/my-new-feature
```

### Weekly Sync with Upstream
```bash
# Keep main in sync with Professor's repo
git checkout main
git fetch upstream
git merge upstream/main
git push origin main

# Update your feature branches
git checkout feature/your-branch
git merge main
git push origin feature/your-branch
```

### Emergency: Undo Last Commit
```bash
# Undo last commit, keep changes
git reset --soft HEAD~1

# Undo last commit, discard changes
git reset --hard HEAD~1
```

### Fix Mistakes
```bash
# Amend last commit message
git commit --amend -m "FEAT: Corrected commit message"

# Add forgotten files to last commit
git add forgotten-file.py
git commit --amend --no-edit

# Discard local changes (use with caution!)
git checkout -- <file>
git reset --hard HEAD
```

---

## Branch Protection Rules (GitHub Settings)

**Recommended settings for `main` branch:**

1. **Go to:** Repository Settings → Branches → Add rule
2. **Branch name pattern:** `main`
3. **Enable:**
   - ✅ Require pull request before merging
   - ✅ Require approvals (at least 1)
   - ✅ Require status checks to pass
   - ✅ Require branches to be up to date before merging
   - ✅ Do not allow bypassing the above settings
4. **Save changes**

---

## Team Collaboration Guidelines

### Code Review Responsibilities

**As an Author:**
- Write clear PR descriptions
- Keep PRs small and focused (< 500 lines)
- Respond to feedback promptly
- Be open to suggestions
- Test your code before requesting review

**As a Reviewer:**
- Review within 24 hours
- Be constructive and specific
- Approve only if code meets standards
- Ask questions if unclear
- Test critical changes locally

### Communication

**Before pushing major changes:**
- Notify team in chat
- Ensure no one else is working on same files
- Coordinate merge timing if needed

**If blocked:**
- Ask for help in team chat
- Tag relevant team member
- Don't stay stuck for more than 2 hours

---

## Conflict Resolution

**If you encounter merge conflicts:**

```bash
# 1. Understand which files conflict
git status

# 2. Open conflicted files and look for markers
# <<<<<<< HEAD
# Your changes
# =======
# Main branch changes
# >>>>>>> main

# 3. Edit files to resolve conflicts
# Remove conflict markers
# Keep the correct code

# 4. Stage resolved files
git add <resolved-files>

# 5. Complete the merge
git commit  # (if merging)
git rebase --continue  # (if rebasing)

# 6. Push
git push origin feature/your-branch
```

**Tips:**
- Communicate with teammate if you both modified same code
- When in doubt, preserve functionality
- Test after resolving conflicts
- Ask for help if complex conflict

---

## Common Scenarios

### Scenario 1: Professor Updates Upstream

```bash
# Sync main with Professor's latest changes
git checkout main
git fetch upstream
git merge upstream/main

# Resolve conflicts if any
# ... fix conflicts ...
git add .
git commit -m "CHORE: Merge upstream updates"

# Push updated main to our fork
git push origin main

# Update your feature branch
git checkout feature/your-branch
git merge main
git push origin feature/your-branch
```

### Scenario 2: Need to Update Feature Branch Mid-Work

```bash
# You're working on feature/taint-tracking
# Main branch was updated by teammate

# Stash your current uncommitted work
git stash

# Update from main
git checkout main
git pull origin main
git checkout feature/taint-tracking
git merge main

# Restore your work
git stash pop

# Resolve conflicts if any, then continue
```

### Scenario 3: Need to Start Urgent Hotfix

```bash
# Save current work
git stash

# Create hotfix branch from main
git checkout main
git pull origin main
git checkout -b fix/urgent-bug

# Fix the bug
# ... make changes ...
git add .
git commit -m "FIX: Resolve critical SQL injection bug"
git push origin fix/urgent-bug

# Create PR and merge quickly

# Return to your feature work
git checkout feature/your-original-branch
git stash pop
```

### Scenario 4: Accidentally Committed to Main

```bash
# Oh no! You committed directly to main!

# 1. Create a branch from current state
git branch feature/accidental-work

# 2. Reset main to match remote
git checkout main
git reset --hard origin/main

# 3. Switch to your new branch
git checkout feature/accidental-work

# 4. Continue work on proper branch
git push -u origin feature/accidental-work
```

---

## Best Practices Summary

### DO ✅
- Always create feature branches from up-to-date main
- Commit frequently with clear messages
- Pull main into your branch before creating PR
- Request code review for all changes
- Delete branches after merging
- Sync with upstream weekly
- Communicate with team about major changes
- Test your code before pushing

### DON'T ❌
- Never commit directly to main
- Don't create huge PRs (keep under 500 lines)
- Don't push broken code
- Don't force push to main
- Don't work on main branch
- Don't leave stale branches around
- Don't merge without approval
- Don't ignore merge conflicts

---

## Helpful Git Aliases (Optional)

Add to your `~/.gitconfig`:

```ini
[alias]
    st = status
    co = checkout
    br = branch
    ci = commit
    unstage = reset HEAD --
    last = log -1 HEAD
    visual = log --graph --oneline --all
    sync = !git checkout main && git pull origin main && git fetch upstream && git merge upstream/main && git push origin main
```

Usage:
```bash
git st              # Instead of git status
git co main         # Instead of git checkout main
git visual          # See branch graph
git sync            # Sync everything at once
```

---

## Getting Help

**If you're stuck:**
1. Check this document
2. Ask in team chat
3. Check git documentation: `git help <command>`
4. Search StackOverflow
5. Ask during team sync meeting

**Common Git Commands Help:**
```bash
git help status
git help merge
git help rebase
git help checkout
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | Nov 16, 2025 | Initial Git Flow documentation |

---

**Remember:** This workflow protects our codebase and ensures smooth collaboration. Follow it consistently!

**Questions?** Ask in team chat or during daily standup.
