<!--
Thanks for the PR. Keep the title Conventional-Commit shaped:
  feat(api): ...    fix(scheduler): ...    chore(deps): ...    docs(readme): ...
-->

## What this PR does

<!-- 1–3 sentences. The "why", not just the "what" — diffs already say what. -->

## Type of change

- [ ] `feat` — new user-visible feature
- [ ] `fix` — bug fix
- [ ] `refactor` — no behavior change
- [ ] `chore` — tooling, deps, repo hygiene
- [ ] `docs` — documentation only
- [ ] `security` — security control or hardening
- [ ] `test` — tests only
- [ ] `perf` — performance only
- [ ] `ci` — pipeline only

## Linked issue

<!-- Closes #123 / Refs #456 / N/A -->

## Verification

<!-- What did you actually run, locally, before pushing? -->

- [ ] `make lint typecheck test`
- [ ] `make security-audit`
- [ ] (if container changed) `make docker-build && make docker-scan`
- [ ] (if endpoint changed) updated `docs/API_USAGE.md`
- [ ] (if user-visible) added entry under `[Unreleased]` in `CHANGELOG.md`

## Notes for the reviewer

<!-- Anything non-obvious: trade-offs, things you considered and rejected, follow-ups left for later. -->

---

By submitting this PR I confirm that:

- [ ] No secrets, `.env` files, or large binaries are included.
- [ ] I'm not reporting a security vulnerability through a PR (those go through `SECURITY.md`).
