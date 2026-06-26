# Security policy & the self-hardening loop

AEGIS runs a daily self-hardening loop that tests itself, makes coverage compound, and
**proposes** improvements via pull request — while remaining **provably unable to weaken
itself or merge without a human**. This document is the human-gate contract.

## The non-negotiable boundary

The AI agent **hunts and proposes**. **Humans approve and merge.** No automated actor can
silently change security-critical code. This is enforced by CI and repo settings, not by
the agent's good behavior.

## Reporting a vulnerability

Report privately to **madhusudan0708@gmail.com** (do not open a public issue for an
unfixed vuln). Confirmed issues become a permanent regression test under
`tests/regression/` **before** the fix lands.

## How the loop is wired (operator setup)

These repo settings are what make the boundary real. Set them once:

### 1. Branch protection on `main`
- Require a pull request before merging; **≥1 human approval**.
- **Require review from Code Owners** (binds `.github/CODEOWNERS` — senior review on
  crypto/auth/secrets/ratchet).
- Require status checks to pass — mark these **required**:
  - `Ratchet guard (REQUIRED)` (from `pr-security.yml` — Subsystem C)
  - `Test battery (PR)` (from `pr-security.yml`)
- Do **not** allow force-push or branch deletion.

```bash
# Example (adjust to your org). Requires admin + gh.
gh api -X PUT repos/:owner/:repo/branches/main/protection \
  -F required_pull_request_reviews.required_approving_review_count=1 \
  -F required_pull_request_reviews.require_code_owner_reviews=true \
  -F 'required_status_checks.contexts[]=Ratchet guard (REQUIRED)' \
  -F 'required_status_checks.contexts[]=Test battery (PR)' \
  -F required_status_checks.strict=true \
  -F enforce_admins=true -F restrictions=
```

### 2. The least-privilege agent token (`AEGIS_AGENT_TOKEN`)
Create a **fine-grained PAT** (or GitHub App installation token) for this repo with the
MINIMUM scopes — and verify it does NOT exceed them:
- ✅ Contents: **Read and write** (to push `security/auto/*` branches)
- ✅ Pull requests: **Read and write** (to open PRs)
- ❌ **No** Administration, Environments, Deployments, Secrets, or Actions write.
- ❌ It must **not** be able to push to `main` (branch protection above blocks it) and
  **cannot approve its own PR** (GitHub forbids self-approval).

Store it as the `AEGIS_AGENT_TOKEN` Actions secret. The optional `ANTHROPIC_API_KEY`
secret enables LLM enrichment; everything still works without it.

### 3. Secret isolation
Scanner credentials (if you add authenticated scans) are injected by CI **only** into the
scanning steps — never into the agent step's environment or logs. The agent treats all
findings as untrusted input.

## The override process (rare, logged)

The ratchet guard (`security/ratchet/ratchet_guard.py`) **blocks** any PR that removes or
weakens a test/control or files down the corpus. A human may consciously override by
applying the **`security-override-approved`** label to the PR. When present:
- the guard logs every constraint it would have enforced (visible in the check output),
- the override still requires the normal human approval + Code Owner review to merge.

Overrides are for genuine, reviewed cases (e.g. retiring a test whose behavior moved
elsewhere). They are the exception; the default is that coverage only grows.

## Staged rollout

Breadth is blast radius. The loop widens one subsystem at a time via
`security/loop.config.yml`: mature gates (deps/SAST/secrets/corpus/ratchet) **enforce**;
newer surfaces (DAST, fuzzing, the agent) start **report-only / pr-only** and harden as
they earn trust. Do not jump straight to enforcing everything.

## What the agent may and may not do

| May | May NOT |
|-----|---------|
| Read code, run the battery | Push to `main` |
| Open PRs to `security/auto/*` | Merge any PR (incl. its own) |
| Add regression tests + propose fixes | Deploy anywhere |
| Flag findings it can't safely fix | Read/write secrets |
| Discard false positives with a logged reason | Weaken a check to clear a finding |
