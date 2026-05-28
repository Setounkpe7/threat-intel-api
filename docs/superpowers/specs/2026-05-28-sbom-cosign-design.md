# SBOM + cosign release pipeline — design

**Status:** Approved (2026-05-28)
**Owner:** Michel-Ange Doubogan
**Branch:** `feat/release-workflow-sbom-cosign`

## Why

The README, the Medium article, and the dev.to article all claim the project's container image is "signed with Sigstore cosign (keyless, OIDC-bound)" and that the CI publishes a SBOM. Neither is implemented today: the image built by `security.yml` is saved as a 1-day GitHub Actions artifact and never pushed to any registry. The doc lies. This spec closes the gap.

## Goals

1. Publish the image to `ghcr.io/setounkpe7/threat-intel-api` on every merge to `main`.
2. Generate a CycloneDX SBOM for that image using Trivy (already in the pipeline).
3. Sign the image with cosign keyless OIDC bound to the GitHub Actions identity.
4. Attach the SBOM to the image as a signed in-toto attestation (`cosign attest --type cyclonedx`), so consumers can verify the SBOM cryptographically links to that exact digest.
5. Add a SLSA build-provenance attestation via `actions/attest-build-provenance` so verifiers learn which workflow, commit, and runner produced the image.
6. Smoke-verify the signature chain end-to-end inside the same job to fail fast on misconfig.
7. Harden the supply chain of the existing CI (`security.yml`) at the same time: pin every third-party action by commit SHA.
8. Correct the documentation so the README/articles match reality, and document the one-time GHCR setup steps in `docs/RELEASING.md`.

## Non-goals (YAGNI)

- Signing images built for pull requests. The trust boundary is "blessed by `main`", not "built by CI".
- Mirroring to Docker Hub or any second registry.
- Adding Syft alongside Trivy. Trivy's CycloneDX output is sufficient.
- Reusable workflows. One consumer means no abstraction.
- GitHub Environment `production` with required reviewers. This is a solo portfolio project; friction outweighs the audit-trail benefit.
- SLSA Level 3 (build isolation, hermetic builds).
- Notation, SCITT, or any signature scheme that is not cosign + Sigstore.

## Architecture

### Trust flow

```
PR opened
   └── security.yml (PR-only gate, unchanged in behavior)
         └── if all 9 jobs pass → PR mergeable
              └── PR merged to main
                   └── release.yml (NEW, push:main only)
                         ├── build image, push to GHCR by digest
                         ├── Trivy → sbom.cdx.json (CycloneDX)
                         ├── cosign sign image@digest (keyless OIDC)
                         ├── cosign attest --type cyclonedx (signed SBOM as OCI referrer)
                         ├── actions/attest-build-provenance (SLSA L2)
                         └── smoke verify (cosign verify + verify-attestation)
```

`release.yml` does **not** gate the PR. Branch protection on `main` already enforces that `security.yml` succeeded before the merge. The release workflow only runs post-merge, on the merge commit's SHA. If it fails, the image is not published — but the code is already on `main`. This is an accepted trade-off because publishing a failed release is reversible (delete the package version), whereas reverting `main` is more disruptive.

### `release.yml` structure

```yaml
name: release

on:
  push:
    branches: [main]
  workflow_dispatch:

permissions: {}                       # deny-all default, escalated per job

concurrency:
  group: release-main
  cancel-in-progress: false           # never abort a half-signed publish

jobs:
  build-publish-sign:
    name: build + publish + sign
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      id-token: write
      attestations: write
    env:
      REGISTRY: ghcr.io
      IMAGE_NAME: ${{ github.repository_owner }}/threat-intel-api
    steps:
      # 1. checkout
      # 2. setup-buildx (cache type=gha shared with security.yml)
      # 3. login to GHCR with github.token (no PAT)
      # 4. docker/metadata-action: tags = sha-<short>, main, latest
      # 5. docker/build-push-action push:true, capture outputs.digest
      # 6. aquasecurity/trivy-action: format cyclonedx, output sbom.cdx.json
      # 7. sigstore/cosign-installer (v2)
      # 8. cosign sign ghcr.io/...@${DIGEST} --yes
      # 9. cosign attest --type cyclonedx --predicate sbom.cdx.json ...@${DIGEST} --yes
      # 10. actions/attest-build-provenance with subject-name + subject-digest
      # 11. smoke verify: cosign verify ...@${DIGEST}
      #     + cosign verify-attestation --type cyclonedx ...@${DIGEST}
```

**Single-job rationale.** All steps share one OIDC token issued at job start. Splitting into separate jobs would either require re-issuing tokens (more places to misconfigure permissions) or passing the digest between jobs via outputs (extra surface for typos and stale references).

**Sign by digest, not by tag.** Tags (`:main`, `:latest`) are mutable. A signature bound to a tag is meaningless because the tag can be repointed to a different image after signing. The digest captured from `docker/build-push-action.outputs.digest` is the only stable identifier.

### Tagging strategy

| Tag | Mutability | Purpose |
|---|---|---|
| `:sha-<7chars>` | immutable | reproducible reference, used in deployments |
| `:main` | mutable | latest commit on `main` |
| `:latest` | mutable | alias for `:main`, conventional for consumers |

The signature is attached to the **digest** of the build. The mutable tags merely point to that digest. When a new release ships, the old digest still exists with its valid signature; the mutable tags move on.

### Action pinning

Every third-party action — in `release.yml` AND in the existing `security.yml` — must be referenced by full commit SHA with a `# vX.Y.Z` comment for human readability. Example:

```yaml
- uses: docker/build-push-action@4f58ea79222b3b9dc2c8bbdd6debcef730109a75  # v6.9.0
```

This is the single most impactful supply-chain hardening step. A compromised action maintainer can retag `@v6` to point at malicious code; a SHA cannot be repointed.

**Scope of pinning work in this PR:**
- `release.yml` — new file, pinned from the start.
- `security.yml` — pin all third-party actions. Inventory:
  - `actions/checkout@v4` (used in 7 jobs)
  - `astral-sh/setup-uv@v6` (used in 5 jobs)
  - `actions/upload-artifact@v4` (used in 4 jobs)
  - `actions/download-artifact@v4` (used in 2 jobs)
  - `gitleaks/gitleaks-action@v2`
  - `hadolint/hadolint-action@v3.1.0`
  - `docker/setup-buildx-action@v3`
  - `docker/build-push-action@v6`
  - `aquasecurity/trivy-action@master` — **especially dangerous** (`@master` = mutable HEAD)
  - `github/codeql-action/upload-sarif@v3`

### GHCR one-time setup

After the first successful push, the maintainer must manually:

1. Visit `https://github.com/users/Setounkpe7/packages/container/threat-intel-api/settings`.
2. **Package visibility → Public.** Without this, unauthenticated `cosign verify` fails because Sigstore cannot resolve the image's manifest.
3. **Manage Actions access → Add repository → `threat-intel-api`** with the **Write** role. This authorises future runs to push to the same package.

These steps are documented in `docs/RELEASING.md` so the next maintainer (or a fresh fork) knows the prerequisite.

## Documentation changes

| File | Change |
|---|---|
| `README.md` (after SAST subsection, ~L230) | Add a new **"### Secret scanning"** subsection documenting Gitleaks. The tool is listed in the stack table (L167) but missing from the detailed breakdown, which is misleading because it implies SAST and SCA cover secret detection — they don't. |
| `README.md` (line ~244) | Refine the cosign sentence to reference `ghcr.io/setounkpe7/threat-intel-api` and clarify "signed on merge to main". |
| `README.md` (new section) | Add **"## Verifying the image"** with a copy-pastable `cosign verify` command bound to the OIDC issuer `https://token.actions.githubusercontent.com` and the certificate identity regex matching this repository. |
| `docs/RELEASING.md` (new, ~30-50 lines) | One-time GHCR setup; the verification commands for image, SBOM attestation, and SLSA provenance; the rollback procedure (delete a published package version). |
| `docs/communication/medium-article.md` (lines 221, 237) | Re-read after implementation; adjust phrasing if the "9 blocking jobs" claim no longer fits (the new release job is post-merge, not a PR gate). |
| `docs/communication/devto-article.md` (line 204) | Same review. |

## Verification

The smoke step at the end of `release.yml` is the gate. Locally, a maintainer can run:

```bash
# Verify the image signature
cosign verify ghcr.io/setounkpe7/threat-intel-api:sha-<short> \
  --certificate-identity-regexp '^https://github\.com/Setounkpe7/threat-intel-api/\.github/workflows/release\.yml@refs/heads/main$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'

# Verify the SBOM attestation
cosign verify-attestation --type cyclonedx ghcr.io/setounkpe7/threat-intel-api:sha-<short> \
  --certificate-identity-regexp '^https://github\.com/Setounkpe7/threat-intel-api/\.github/workflows/release\.yml@refs/heads/main$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'

# Verify the SLSA build provenance
gh attestation verify oci://ghcr.io/setounkpe7/threat-intel-api:sha-<short> \
  --repo Setounkpe7/threat-intel-api
```

All three must return success. Failure indicates either an unsigned image, a misconfigured workflow identity, or a tampered registry.

## Threat model (what the design protects against, what it doesn't)

**Protects against**
- Registry compromise that swaps layers under an existing tag.
- Typosquatted image names (`ghcr.io/setounkpe7-evil/threat-intel-api`) — the certificate identity binds to *this* repo.
- A consumer pulling an outdated/unsigned image by mistake.
- An attacker tampering with the SBOM independently of the image.

**Does not protect against**
- A compromised `main` branch. If an attacker merges a malicious PR, the resulting image is signed with a valid signature.
- Vulnerable dependencies inside the signed image. Signing proves provenance, not safety.
- A malicious unpinned action that runs during the signed build. **This is why action pinning is in scope for this same PR.**
- The maintainer publishing a backdoor through a legitimate PR.

## Implementation order

1. Cut `feat/release-workflow-sbom-cosign` from `dev`. **Done.**
2. SHA-pin all third-party actions in `security.yml` (mechanical change, smallest diff first).
3. Add `release.yml` with the full step sequence and pinned actions.
4. Add `docs/RELEASING.md`.
5. Update `README.md` (refine cosign sentence + add "Verifying the image" section).
6. Re-read the two communication articles; adjust phrasing if needed.
7. PR to `dev`, full security gate runs, verify it still passes.
8. After merge to `dev` and then `dev → main`, the first run of `release.yml` fires. Maintainer performs the GHCR one-time setup (visibility public + repo write access).
9. Re-run `release.yml` via `workflow_dispatch` to confirm the chain works end-to-end.

## Rollback

If `release.yml` produces a broken image:

1. Delete the offending package version on GHCR (`Settings → Packages → threat-intel-api → Versions → Delete`).
2. Push a follow-up commit to `main` (via the normal PR flow) that triggers a fresh release.

If `release.yml` itself is broken and fires on every push:

1. Revert the offending commit on `main` via PR.
2. Or temporarily disable the workflow in `Settings → Actions → release.yml → Disable workflow`.

## Open questions

None at design time. All decisions are captured in the conversation log on this branch:

- Trigger = merge to main (vs every PR or tagged release)
- Registry = GHCR (vs Docker Hub or both)
- SBOM tool = Trivy (vs Syft or both)
- Signing scope = image + SBOM attestation (vs image only or + SLSA provenance which was upgraded to "yes" after agent review)
- Workflow placement = standalone `release.yml` on `push:main` (vs in-`security.yml` conditional or `workflow_run`-dependent)
