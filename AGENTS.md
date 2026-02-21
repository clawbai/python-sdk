# Default workflow

- After completing any code change, automatically:
1. create a feature branch (if needed)
2. commit with a clear message
3. push to origin
4. open a PR to `main`
5. if checks are green (or if no checks are required), merge the PR
6. switch local branch back to `main` and pull latest

# PR policy

- Use squash merge.
- PR title format: `<type>: <short summary>`.
- PR body must include: Summary, Testing, Risks.

# Safety rules

- Do not auto-merge if:
1. merge conflicts exist
2. required checks fail
3. PR is marked draft
- In those cases, stop and report.
