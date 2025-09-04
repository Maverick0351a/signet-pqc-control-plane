# Branch Protection Policy

Recommended GitHub branch protection settings for `main`:

1. Require a pull request before merging.
   - Require at least 1 approving review.
   - Dismiss stale approvals when new commits are pushed.
2. Require status checks to pass before merging.
   - Required checks: CI, CodeQL, OpenSSF Scorecard, codecov/patch, codecov/project.
3. Require branches to be up to date before merging.
4. Require signed commits (optional, if enforcing GPG/SSH signing).
5. Include administrators (optional, for stronger guarantees).
6. Require CODEOWNERS review (enabled via CODEOWNERS file).
7. Block force pushes and deletions on `main`.

Automation Notes:
- Adjust required checks names after first successful run (they must match exactly).
- Use the GitHub UI or API to apply these rules; this repo documents but does not enforce them automatically.
