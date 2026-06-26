# Contributing to AEGIS

AEGIS is a security tool, so the contribution rules are stricter than usual. The core
rule: **the loop may only add constraints, never remove them.**

## The ratchet (read this first)

- Every confirmed vulnerability gets a **permanent regression test** under
  `tests/regression/`, committed **before** its fix, in the **same** PR.
- The regression corpus is **append-only**. Files locked in
  `security/ratchet/corpus.lock.json` are immutable.
- `baseline_tests.txt` lists tests that must always exist; it only grows.

The `Ratchet guard (REQUIRED)` check enforces all of this. It will **block** a PR that
removes/renames a baseline test, alters a locked regression test, or shrinks the lockfiles.

## Adding a regression test (the only supported way)

```bash
# 1. Write the test (it should FAIL against the vulnerability):
$EDITOR tests/regression/test_REG_$(date +%Y%m%d)_0003_my_issue.py

# 2. Lock it into the append-only corpus and refresh the baseline:
python security/ratchet/update_corpus.py \
  --add tests/regression/test_REG_$(date +%Y%m%d)_0003_my_issue.py \
  --id REG-$(date +%Y%m%d)-0003 \
  --threat "S1/A07" \
  --summary "one-line description"

# 3. Then add the fix in the same PR. Label the PR `security-fix`.
```

If you add any other tests, run `python security/ratchet/update_corpus.py --sync-baseline`
so they’re guaranteed forever too.

## Before opening a PR

```bash
pip install -r requirements-dev.txt && pip install -e ".[django,sanitize]"
pytest -q                                   # adversarial + fail-closed + regression + fuzz
bandit -r aegis -c pyproject.toml -ll
pip-audit -r requirements.txt --strict
python security/ratchet/ratchet_guard.py    # the same gate CI runs
```

## Touching security-critical code

Changes to crypto, auth, secrets, the ratchet, the CI gates, or the agent require **senior
review** (see `.github/CODEOWNERS`). Do not work around this.

## Forbidden

- Weakening, disabling, or relaxing a test/check/control to clear a finding. If a finding
  can only be resolved that way, flag it for human review — never do it silently.
- Removing a regression test or baseline entry without the `security-override-approved`
  label and Code Owner sign-off.
- Granting any automated actor the ability to merge, deploy, or write to `main`.

## Overrides

Genuine, reviewed removals use the `security-override-approved` label, which the ratchet
guard logs. See `SECURITY.md` for the process.
