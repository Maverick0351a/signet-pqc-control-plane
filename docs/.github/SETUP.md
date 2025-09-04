# Repository Governance & Protection Setup

This document describes the baseline repository protection and required checks configuration.

## Branch Protection (main)
Apply a protection rule to the `main` branch with these settings:

| Setting | Value |
|---------|-------|
| Require a pull request before merging | Enabled |
| Required approvals | 1 |
| Dismiss stale pull request approvals when new commits are pushed | Enabled |
| Require review from Code Owners | (Optional) Enable if CODEOWNERS granular control desired |
| Require status checks to pass before merging | Enabled |
| Status checks that are required | `CI`, `CodeQL`, `OpenSSF Scorecard` (optional gating) |
| Require branches to be up to date before merging | Enabled |
| Require signed commits | Recommended (enable if all contributors can sign) |
| Require linear history | Recommended |
| Include administrators | Recommended |
| Allow force pushes | Disabled |
| Allow deletions | Disabled |

## Workflow Permissions
At the org or repo level set default workflow permissions to `Read repository contents permission`. Write permissions are granted per job only when needed (e.g., `security-events: write` for CodeQL and Scorecard uploads, `id-token: write` for OIDC).

## Dependabot
Dependabot weekly updates are configured for `pip` and `github-actions`. Add additional ecosystems (e.g., `docker`) if container manifests are introduced.

## Adding a New Required Check
Add the workflow name (job-level if needed) into the branch protection rule after it has run successfully at least once on the default branch.

## Security Hardening Notes
- All actions are pinned to full-length commit SHAs.
- Least-privilege permissions at both workflow and job levels.
- Consider enabling secret scanning and Dependabot alerts in repository settings.
- Add `CODEOWNERS` reviewers for critical paths (already present).

