# SBOM + cosign release pipeline — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a post-merge release workflow that publishes the image to GHCR, generates a CycloneDX SBOM, signs the image with cosign keyless OIDC, attaches the SBOM as a signed attestation, and produces a SLSA L2 build provenance — while hardening the existing `security.yml` by SHA-pinning all third-party actions and fixing the gitleaks omission in the README.

**Architecture:** A new standalone `.github/workflows/release.yml` triggers on `push: branches: [main]` only (post-PR, post-merge). It does NOT gate the PR — that responsibility stays with `security.yml`. The release job is a single job that owns the entire chain (build → push by digest → SBOM → sign → attest → SLSA provenance → smoke verify), so one OIDC token frame covers every signing operation.

**Tech Stack:** GitHub Actions, Docker Buildx (`type=gha` cache shared with security.yml), GHCR (`ghcr.io/setounkpe7/threat-intel-api`), Trivy (CycloneDX SBOM), cosign v2 (keyless OIDC via Sigstore Fulcio + Rekor), `actions/attest-build-provenance` for SLSA L2.

**Spec:** [docs/superpowers/specs/2026-05-28-sbom-cosign-design.md](../specs/2026-05-28-sbom-cosign-design.md)

---

## File Structure

| File | Status | Responsibility |
|---|---|---|
| `.github/workflows/release.yml` | **create** | Post-merge publish + sign workflow |
| `.github/workflows/security.yml` | modify | SHA-pin all third-party actions |
| `docs/RELEASING.md` | **create** | One-time GHCR setup + verification commands + rollback |
| `README.md` | modify | Add Secret scanning section (gitleaks), refine cosign mention, add Verifying section |
| `docs/communication/medium-article.md` | review | Re-read after impl, adjust if "9 blocking jobs" phrasing no longer fits |
| `docs/communication/devto-article.md` | review | Same review |

---

## How "tests" work in this plan

There is no pytest equivalent for CI workflows. Verification cadence:

- **Local syntax check:** `actionlint .github/workflows/<file>.yml` (Go binary, installs in seconds; catches typos, unknown actions, bad expressions)
- **PR feedback loop:** every commit on `feat/release-workflow-sbom-cosign` re-runs `security.yml` as a PR check. SHA-pinning changes are tested here.
- **Release workflow can only fire on `push: main`**, so `release.yml` itself is verified post-merge in Phase B. The `workflow_dispatch:` trigger we include lets a maintainer re-run it from the UI without waiting for a new commit.

The "failing test first" discipline translates here as: **add `actionlint` to validation steps** before changing workflow files, so we know a structural break shows up immediately.

---

## Phase A — Branch work (on `feat/release-workflow-sbom-cosign`)

### Task 1: SHA-pin all third-party actions in `security.yml`

**Why first:** Mechanical, smallest diff first. If this breaks something we find out before adding any release logic.

**Files:**
- Modify: `.github/workflows/security.yml` (10 action references)

**Actions to pin (inventory from current file):**

| Action | Currently | Pin to |
|---|---|---|
| `actions/checkout@v4` (×7 jobs) | tag | SHA of `v4.2.x` latest |
| `astral-sh/setup-uv@v6` (×5 jobs) | tag | SHA of `v6.x` latest |
| `actions/upload-artifact@v4` (×4 jobs) | tag | SHA of `v4.x` latest |
| `actions/download-artifact@v4` (×2 jobs) | tag | SHA of `v4.x` latest |
| `gitleaks/gitleaks-action@v2` | tag | SHA of `v2.x` latest |
| `hadolint/hadolint-action@v3.1.0` | tag | SHA of `v3.1.0` |
| `docker/setup-buildx-action@v3` | tag | SHA of `v3.x` latest |
| `docker/build-push-action@v6` | tag | SHA of `v6.x` latest |
| `aquasecurity/trivy-action@master` (×2 uses) | **mutable HEAD ⚠️** | SHA of latest stable release tag |
| `github/codeql-action/upload-sarif@v3` | tag | SHA of `v3.x` latest |

- [ ] **Step 1.1: Install actionlint locally for syntax validation**

```bash
# Linux x86_64 — pick the matching binary for your platform from
# https://github.com/rhysd/actionlint/releases
curl -sSfL https://raw.githubusercontent.com/rhysd/actionlint/main/scripts/download-actionlint.bash | bash
sudo mv ./actionlint /usr/local/bin/
actionlint --version
```

Expected: prints `1.x.y` and exits 0.

- [ ] **Step 1.2: Baseline-validate security.yml BEFORE any change**

```bash
actionlint .github/workflows/security.yml
echo "exit=$?"
```

Expected: no output, `exit=0`. If it errors here, the file already had issues — fix them before SHA-pinning.

- [ ] **Step 1.3: Fetch every SHA via GitHub API and build a substitution table**

Use this script (paste into a temp file `pin.sh`, run it, capture output):

```bash
#!/usr/bin/env bash
set -euo pipefail

pin() {
  local owner_repo="$1" ref="$2"
  local sha
  sha=$(gh api "/repos/${owner_repo}/git/refs/tags/${ref}" --jq '.object.sha')
  # If tag is annotated, resolve to the commit
  local type
  type=$(gh api "/repos/${owner_repo}/git/objects/${sha}" --jq '.type' 2>/dev/null || echo "commit")
  if [[ "$type" == "tag" ]]; then
    sha=$(gh api "/repos/${owner_repo}/git/tags/${sha}" --jq '.object.sha')
  fi
  echo "${owner_repo}@${sha}  # ${ref}"
}

pin actions/checkout                       v4.2.2
pin astral-sh/setup-uv                     v6.0.1
pin actions/upload-artifact                v4.4.3
pin actions/download-artifact              v4.1.8
pin gitleaks/gitleaks-action               v2.3.9
pin hadolint/hadolint-action               v3.1.0
pin docker/setup-buildx-action             v3.7.1
pin docker/build-push-action               v6.9.0
pin aquasecurity/trivy-action              0.28.0
pin github/codeql-action/upload-sarif      v3.27.0
```

**Important:** The version numbers above are illustrative starting points. Before running, **check the latest stable release** for each repo and update the version arguments. The CLI lookup is the same; only the version number changes. Run `bash pin.sh` and save the output — you'll paste each SHA into the YAML in Step 1.4.

- [ ] **Step 1.4: Apply the SHA-pinning edits**

For each `uses:` line in `.github/workflows/security.yml`, replace the `@vX` reference with `@<sha>  # vX.Y.Z` from the table generated in Step 1.3.

Example transformation:

```yaml
# BEFORE
- uses: actions/checkout@v4

# AFTER
- uses: actions/checkout@<paste-sha-here>  # v4.2.2
```

Apply this to every `uses:` line referenced in the inventory table at the top of this task. Be especially careful with `aquasecurity/trivy-action@master` — both occurrences (lines ~206 and ~217 in the current file) must be pinned to the SAME SHA.

- [ ] **Step 1.5: Re-run actionlint to confirm syntax is still valid**

```bash
actionlint .github/workflows/security.yml
echo "exit=$?"
```

Expected: no output, `exit=0`.

- [ ] **Step 1.6: Commit**

```bash
git add .github/workflows/security.yml
git commit -m "$(cat <<'EOF'
chore(ci): SHA-pin all third-party actions in security.yml

Pins every external action by commit SHA with a # vX.Y.Z comment.
Closes the supply-chain gap where a compromised action maintainer could
retag a version (e.g. aquasecurity/trivy-action@master is mutable HEAD)
and inject malicious code into the signed image build.

Refs spec docs/superpowers/specs/2026-05-28-sbom-cosign-design.md
EOF
)"
```

- [ ] **Step 1.7: Push and verify PR check passes**

```bash
git push -u origin feat/release-workflow-sbom-cosign
gh pr create --base dev --title "feat: SBOM + cosign release pipeline" --draft --body "Tracking PR for the cosign/SBOM work. Spec: docs/superpowers/specs/2026-05-28-sbom-cosign-design.md"
# Wait for security.yml to run, then:
gh pr checks
```

Expected: all 9 security.yml jobs pass with the new pinned SHAs.

---

### Task 2: Create `release.yml` skeleton (triggers, permissions, concurrency, empty job)

**Why second:** Get the workflow file in place with strict permissions before adding any signing logic. Easier to review structure separately.

**Files:**
- Create: `.github/workflows/release.yml`

- [ ] **Step 2.1: Create the skeleton**

Create `.github/workflows/release.yml` with this exact content:

```yaml
name: release

# Fires only after a successful merge to main. security.yml has already
# gated the PR; this workflow's job is to publish and sign the merge-commit
# image, not to re-validate it.
on:
  push:
    branches: [main]
  workflow_dispatch:

# Deny-all by default; each job escalates only what it needs.
permissions: {}

# Never abort a half-signed publish — wait for the previous run to finish.
concurrency:
  group: release-main
  cancel-in-progress: false

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository_owner }}/threat-intel-api

jobs:
  build-publish-sign:
    name: build + publish + sign
    runs-on: ubuntu-latest
    permissions:
      contents: read         # checkout
      packages: write        # push to GHCR
      id-token: write        # OIDC for cosign keyless + attestations
      attestations: write    # for actions/attest-build-provenance
    steps:
      - name: Placeholder
        run: echo "skeleton — fleshed out in following tasks"
```

- [ ] **Step 2.2: Validate locally with actionlint**

```bash
actionlint .github/workflows/release.yml
echo "exit=$?"
```

Expected: no output, `exit=0`.

- [ ] **Step 2.3: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci(release): add release.yml skeleton (triggers, permissions, concurrency)"
```

---

### Task 3: Add build + push by digest to `release.yml`

**Files:**
- Modify: `.github/workflows/release.yml` (replace the Placeholder step)

- [ ] **Step 3.1: Replace the Placeholder step with build + push steps**

Open `.github/workflows/release.yml`. Replace the single `- name: Placeholder` step with the following sequence. Use the SHAs you fetched in Task 1 Step 1.3 for the actions also used here (`checkout`, `setup-buildx-action`, `build-push-action`).

```yaml
      - name: Checkout
        uses: actions/checkout@<paste-sha>  # v4.2.2

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@<paste-sha>  # v3.7.1

      - name: Log in to GHCR
        uses: docker/login-action@<lookup-and-paste-sha>  # v3.3.0
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Compute image tags & labels
        id: meta
        uses: docker/metadata-action@<lookup-and-paste-sha>  # v5.6.1
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=raw,value=sha-${{ github.sha }}
            type=raw,value=main
            type=raw,value=latest

      - name: Build and push by digest
        id: build
        uses: docker/build-push-action@<paste-sha>  # v6.9.0
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          build-args: |
            GIT_SHA=${{ github.sha }}
            BUILD_DATE=${{ github.event.repository.updated_at }}
            VERSION=${{ github.ref_name }}
          cache-from: type=gha
          cache-to: type=gha,mode=max

      - name: Capture image reference by digest
        id: ref
        run: |
          echo "image=${REGISTRY}/${IMAGE_NAME}@${{ steps.build.outputs.digest }}" >> "$GITHUB_OUTPUT"
          echo "image=${REGISTRY}/${IMAGE_NAME}@${{ steps.build.outputs.digest }}"
```

- [ ] **Step 3.2: Look up and paste SHAs for `docker/login-action` and `docker/metadata-action`**

```bash
gh api /repos/docker/login-action/git/refs/tags/v3.3.0 --jq '.object.sha'
gh api /repos/docker/metadata-action/git/refs/tags/v5.6.1 --jq '.object.sha'
```

Replace both `<lookup-and-paste-sha>` markers in the file.

- [ ] **Step 3.3: Validate**

```bash
actionlint .github/workflows/release.yml
echo "exit=$?"
```

Expected: `exit=0`.

- [ ] **Step 3.4: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci(release): build and push image to GHCR by digest"
```

---

### Task 4: Add SBOM generation (Trivy CycloneDX) and cosign install

**Files:**
- Modify: `.github/workflows/release.yml`

- [ ] **Step 4.1: Append SBOM and cosign install steps after the build step**

After the `Capture image reference by digest` step, add:

```yaml
      - name: Generate CycloneDX SBOM with Trivy
        uses: aquasecurity/trivy-action@<paste-same-sha-as-security-yml>  # 0.28.0
        with:
          image-ref: ${{ steps.ref.outputs.image }}
          format: cyclonedx
          output: sbom.cdx.json

      - name: Sanity-check the SBOM file exists and has components
        run: |
          test -s sbom.cdx.json
          jq -e '.components | length > 0' sbom.cdx.json > /dev/null
          echo "SBOM contains $(jq '.components | length' sbom.cdx.json) components"

      - name: Install cosign
        uses: sigstore/cosign-installer@<lookup-and-paste-sha>  # v3.7.0
        with:
          cosign-release: v2.4.1
```

- [ ] **Step 4.2: Look up the cosign-installer SHA**

```bash
gh api /repos/sigstore/cosign-installer/git/refs/tags/v3.7.0 --jq '.object.sha'
```

Paste it into the YAML.

- [ ] **Step 4.3: Validate and commit**

```bash
actionlint .github/workflows/release.yml
git add .github/workflows/release.yml
git commit -m "ci(release): generate CycloneDX SBOM with Trivy and install cosign"
```

---

### Task 5: Add cosign sign + cosign attest SBOM

**Files:**
- Modify: `.github/workflows/release.yml`

- [ ] **Step 5.1: Append signing and attestation steps after the cosign install**

```yaml
      - name: Sign the image with cosign keyless OIDC
        env:
          IMAGE: ${{ steps.ref.outputs.image }}
        run: |
          cosign sign --yes "${IMAGE}"

      - name: Attest the SBOM as a signed in-toto predicate
        env:
          IMAGE: ${{ steps.ref.outputs.image }}
        run: |
          cosign attest --yes \
            --type cyclonedx \
            --predicate sbom.cdx.json \
            "${IMAGE}"
```

- [ ] **Step 5.2: Validate and commit**

```bash
actionlint .github/workflows/release.yml
git add .github/workflows/release.yml
git commit -m "ci(release): sign image and attest SBOM with cosign keyless OIDC"
```

---

### Task 6: Add SLSA build-provenance attestation + smoke verify

**Files:**
- Modify: `.github/workflows/release.yml`

- [ ] **Step 6.1: Append SLSA provenance and smoke verify steps**

```yaml
      - name: Generate SLSA build provenance attestation
        uses: actions/attest-build-provenance@<lookup-and-paste-sha>  # v2.1.0
        with:
          subject-name: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          subject-digest: ${{ steps.build.outputs.digest }}
          push-to-registry: true

      - name: Smoke verify the complete signature chain
        env:
          IMAGE: ${{ steps.ref.outputs.image }}
          IDENTITY_REGEX: ^https://github\.com/${{ github.repository }}/\.github/workflows/release\.yml@refs/heads/main$
          OIDC_ISSUER: https://token.actions.githubusercontent.com
        run: |
          echo "=== verifying image signature ==="
          cosign verify "${IMAGE}" \
            --certificate-identity-regexp "${IDENTITY_REGEX}" \
            --certificate-oidc-issuer "${OIDC_ISSUER}"

          echo "=== verifying SBOM attestation ==="
          cosign verify-attestation "${IMAGE}" \
            --type cyclonedx \
            --certificate-identity-regexp "${IDENTITY_REGEX}" \
            --certificate-oidc-issuer "${OIDC_ISSUER}"

          echo "=== signature chain OK ==="
```

- [ ] **Step 6.2: Look up the attest-build-provenance SHA**

```bash
gh api /repos/actions/attest-build-provenance/git/refs/tags/v2.1.0 --jq '.object.sha'
```

Paste into the YAML.

**Note on the smoke verify identity regex:** when `workflow_dispatch` is used instead of `push: main`, the certificate identity ends with `@refs/heads/main` only when the dispatch is targeted at `main`. If a maintainer dispatches the workflow from a feature branch, this regex will fail — that is intentional (we only trust main-branch identities).

- [ ] **Step 6.3: Validate and commit**

```bash
actionlint .github/workflows/release.yml
git add .github/workflows/release.yml
git commit -m "ci(release): add SLSA provenance attestation and smoke-verify the chain"
```

---

### Task 7: Create `docs/RELEASING.md`

**Files:**
- Create: `docs/RELEASING.md`

- [ ] **Step 7.1: Write `docs/RELEASING.md`**

Create the file with this content:

````markdown
# Releasing — maintainer guide

This document covers the one-time setup required after the first run of
`.github/workflows/release.yml`, and the commands consumers use to verify
a published image.

## One-time GHCR setup

After the first successful run of `release.yml` (post-merge to `main`):

1. **Make the package public** so unauthenticated `cosign verify` works.
   Visit `https://github.com/users/Setounkpe7/packages/container/threat-intel-api/settings`
   and click **Change visibility → Public**.

2. **Grant the repository write access to its own package.** On the same
   settings page, under **Manage Actions access**, click **Add Repository**
   and select `threat-intel-api` with the **Write** role. This allows
   subsequent runs of the workflow to push to the same package.

These two clicks only need to be done once per package. If the package is
deleted and recreated, repeat them.

## Verifying a published image

The release workflow signs every image and attaches three artifacts:

- a cosign keyless signature (Sigstore Fulcio cert, Rekor log entry)
- a CycloneDX SBOM attestation (`cosign attest --type cyclonedx`)
- a SLSA L2 build provenance attestation (`actions/attest-build-provenance`)

Any consumer can verify all three. Replace `<short-sha>` with the 7-char
prefix of the commit you want to verify (visible on the GHCR package
page).

```bash
IMAGE=ghcr.io/setounkpe7/threat-intel-api:sha-<short-sha>
IDENTITY_REGEX='^https://github\.com/Setounkpe7/threat-intel-api/\.github/workflows/release\.yml@refs/heads/main$'
OIDC_ISSUER=https://token.actions.githubusercontent.com

# 1. Image signature
cosign verify "${IMAGE}" \
  --certificate-identity-regexp "${IDENTITY_REGEX}" \
  --certificate-oidc-issuer "${OIDC_ISSUER}"

# 2. SBOM attestation
cosign verify-attestation --type cyclonedx "${IMAGE}" \
  --certificate-identity-regexp "${IDENTITY_REGEX}" \
  --certificate-oidc-issuer "${OIDC_ISSUER}"

# 3. SLSA build provenance
gh attestation verify oci://${IMAGE} \
  --repo Setounkpe7/threat-intel-api
```

All three commands must exit 0. A failure indicates either an unsigned
image, a misconfigured workflow identity, or a tampered registry.

## Rollback

### A broken image was published

```bash
# Delete the offending package version from GHCR
gh api -X DELETE \
  /user/packages/container/threat-intel-api/versions/<version-id>
```

Find `<version-id>` at `https://github.com/users/Setounkpe7/packages/container/threat-intel-api/versions`.

Then push a follow-up fix through the normal `feat/* → dev → main` PR
flow. The next merge to `main` triggers a fresh `release.yml` run.

### The release workflow itself is broken

Two options:

1. **Revert via PR.** Open a PR that reverts the offending commit on
   `main`. The next merge fires `release.yml` again with the reverted
   state.

2. **Disable the workflow.** `Settings → Actions → release.yml →
   Disable workflow`. Re-enable once the fix is in. Use this if the
   workflow is currently failing in a way that publishes broken state on
   every push.

## Triggering a re-release without a code change

The workflow accepts `workflow_dispatch`. Trigger from the Actions tab,
or via CLI:

```bash
gh workflow run release.yml --ref main
```

This re-runs the full pipeline on the current `main` HEAD. Useful when:

- The previous run failed mid-chain and you want to retry.
- You need a fresh signature on the same code (e.g., after rotating
  Sigstore trust roots).
````

- [ ] **Step 7.2: Commit**

```bash
git add docs/RELEASING.md
git commit -m "docs(release): document GHCR setup, verification, and rollback procedures"
```

---

### Task 8: Update `README.md` — add Secret scanning section, refine cosign mention, add Verifying section

**Files:**
- Modify: `README.md` (3 edits)

- [ ] **Step 8.1: Add the Secret scanning subsection**

Open `README.md`. Locate the **`### Dependency security (SCA)`** heading (around line 232). **Above** it (between the SAST list ending at line 230 and the SCA heading at line 232), insert:

```markdown

### Secret scanning

- **Gitleaks** — scans the full git history on every PR; fails the gate
  on any committed credential, key, or token

```

Result around lines 225-238:

```markdown
### Static analysis (SAST)

- **Bandit** — Python AST audit (CWE coverage tuned for web)
- **Semgrep** — pattern rules including OWASP Top 10
- **Ruff** with security ruleset
- **mypy** — strict mode on `src/`

### Secret scanning

- **Gitleaks** — scans the full git history on every PR; fails the gate
  on any committed credential, key, or token

### Dependency security (SCA)

- **pip-audit** — runtime CVE scan against `requirements.lock`
- **Dependabot** — weekly updates, grouped, auto-merged on green
- **CycloneDX SBOM** — generated and attached to release artifacts
```

- [ ] **Step 8.2: Refine the cosign mention**

Locate the line:

```markdown
- Image is signed with **Sigstore cosign** (keyless, OIDC-bound)
```

Replace it with:

```markdown
- Image is published to **`ghcr.io/setounkpe7/threat-intel-api`** on merge
  to `main`, signed with **Sigstore cosign** (keyless, OIDC-bound to this
  repo's GitHub Actions identity), and shipped with a CycloneDX SBOM and
  SLSA L2 build-provenance attestation
```

- [ ] **Step 8.3: Add a "Verifying the image" section**

Locate the **`### Runtime security`** heading (around line 246). **Above** it (after the Container security list ends), insert:

```markdown

### Verifying a published image

Any consumer can cryptographically verify the image, the SBOM, and the
build provenance:

```bash
IMAGE=ghcr.io/setounkpe7/threat-intel-api:sha-<short-sha>
IDENTITY_REGEX='^https://github\.com/Setounkpe7/threat-intel-api/\.github/workflows/release\.yml@refs/heads/main$'
OIDC_ISSUER=https://token.actions.githubusercontent.com

cosign verify "${IMAGE}" \
  --certificate-identity-regexp "${IDENTITY_REGEX}" \
  --certificate-oidc-issuer "${OIDC_ISSUER}"

cosign verify-attestation --type cyclonedx "${IMAGE}" \
  --certificate-identity-regexp "${IDENTITY_REGEX}" \
  --certificate-oidc-issuer "${OIDC_ISSUER}"

gh attestation verify oci://${IMAGE} --repo Setounkpe7/threat-intel-api
```

All three must exit 0. See [`docs/RELEASING.md`](docs/RELEASING.md) for
the rollback procedure and the one-time GHCR setup.

```

- [ ] **Step 8.4: Commit**

```bash
git add README.md
git commit -m "docs(readme): document gitleaks, refine cosign claim, add Verifying section"
```

---

### Task 9: Review the two communication articles, adjust phrasing if needed

**Files:**
- Modify (if needed): `docs/communication/medium-article.md`
- Modify (if needed): `docs/communication/devto-article.md`

- [ ] **Step 9.1: Read the current claims in context**

```bash
grep -n -B1 -A3 -iE "cosign|sbom|9 blocking" docs/communication/medium-article.md docs/communication/devto-article.md
```

Read each match in its surrounding paragraph. The known questionable claims are:

- `medium-article.md:221` — *"Trivy, cosign, distroless-style runtime, SBOM publication and the 9-job CI gate landed across M3 and M3a"*. After this PR, cosign and SBOM landed but **not in M3/M3a** — they landed now. The phrasing is historical narrative; **leave as-is** since articles are dated artefacts (the article's voice describes the past from a fixed point).
- `medium-article.md:237` — *"Images are signed with Sigstore cosign, keyless, OIDC-bound to the GitHub Actions identity"*. **True after this PR.** Leave.
- `devto-article.md:204` — *"CI gate is 9 blocking jobs: ..., Hadolint, Trivy (fails on CRITICAL+HIGH > 0), SBOM publish, ..., full pytest with 86% coverage threshold"*. **"SBOM publish" is not a CI gate job** — it's a post-merge release step that does not block PRs. Coverage threshold is 80, not 86.

- [ ] **Step 9.2: Fix the `devto-article.md` line 204**

Open `docs/communication/devto-article.md`. Replace the sentence containing *"CI gate is 9 blocking jobs"* with the accurate version. Find:

```markdown
Stack: FastAPI, SQLAlchemy 2.0, PostgreSQL, Pydantic v2, httpx + tenacity, structlog, Sentry. Runs in a 195 MB Alpine container, non-root, no `pip` in the runtime image, signed with cosign. CI gate is 9 blocking jobs: Bandit, Semgrep, Ruff (security ruleset), mypy strict, pip-audit, Hadolint, Trivy (fails on `CRITICAL+HIGH > 0`), SBOM publish, full pytest with 86% coverage threshold.
```

Replace with:

```markdown
Stack: FastAPI, SQLAlchemy 2.0, PostgreSQL, Pydantic v2, httpx + tenacity, structlog, Sentry. Runs in a 195 MB Alpine container, non-root, no `pip` in the runtime image, signed with cosign on merge to main. CI gate is 9 blocking jobs: Bandit, Semgrep, Gitleaks, Ruff (security ruleset), mypy strict, pip-audit, Hadolint, Trivy (fails on `CRITICAL` with a fix available), full pytest with 80% coverage threshold, plus alembic migration roundtrip on Postgres. SBOM and cosign signing run post-merge in a separate release workflow.
```

- [ ] **Step 9.3: Leave `medium-article.md` as-is unless you spot a factual error**

The Medium article uses past-tense narrative voice. As long as cosign and SBOM are actually in place after this PR, the article's claim that they "landed across M3 and M3a" is a forgivable historical approximation. Do not edit unless you spot a hard factual error.

- [ ] **Step 9.4: Commit**

```bash
git add docs/communication/devto-article.md
git commit -m "docs(comm): correct devto-article CI gate description"
```

---

### Task 10: Push and convert PR to ready-for-review

**Files:** none (git/gh operations only)

- [ ] **Step 10.1: Push all commits**

```bash
git push
```

- [ ] **Step 10.2: Verify security.yml passes on the PR**

```bash
gh pr checks
```

Expected: all 9 jobs in `security.yml` are passing. The new `release.yml` does NOT run on PR (only on push to main), so it won't appear in checks.

- [ ] **Step 10.3: Convert the draft PR to ready-for-review**

```bash
gh pr ready
```

- [ ] **Step 10.4: Wait for merge to `dev`, then open the `dev → main` PR**

After the PR to `dev` is merged, open the promotion PR:

```bash
git checkout dev
git pull
gh pr create --base main --head dev --title "release: SBOM + cosign release pipeline + supply-chain hardening" \
  --body "Promotes the SBOM + cosign release pipeline from dev to main. First merge fires release.yml. See docs/RELEASING.md for the GHCR one-time setup that must follow."
```

---

## Phase B — Post-merge operator tasks

These tasks run **after** the `dev → main` PR is merged. They cannot be automated because they involve GitHub UI clicks and local verification commands a maintainer runs against the published artefacts.

### Task 11: GHCR one-time setup

- [ ] **Step 11.1: Wait for the first `release.yml` run to complete**

```bash
gh run list --workflow=release.yml --limit=1
gh run watch
```

Expected: the run completes successfully. If it fails on the push step with "denied: installation not allowed to Create organization package", that's the first-run permission issue — proceed to Step 11.2 anyway to fix it, then re-trigger via `workflow_dispatch`.

- [ ] **Step 11.2: Make the package public**

In a browser, open:

```
https://github.com/users/Setounkpe7/packages/container/threat-intel-api/settings
```

Scroll to **Danger Zone → Change visibility**. Set to **Public**. Confirm.

- [ ] **Step 11.3: Grant the repository write access to its own package**

On the same settings page, **Manage Actions access** → **Add Repository** → search and select `threat-intel-api` → set role to **Write**.

- [ ] **Step 11.4: Re-trigger `release.yml` to confirm the chain works end-to-end**

```bash
gh workflow run release.yml --ref main
gh run watch
```

Expected: the run completes successfully, including the smoke-verify step at the end.

---

### Task 12: Local verification of the published artefacts

- [ ] **Step 12.1: Install cosign and gh CLI locally if not already present**

```bash
cosign version || (curl -sSfL -o cosign 'https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64' && chmod +x cosign && sudo mv cosign /usr/local/bin/)
gh --version
```

- [ ] **Step 12.2: Resolve the short SHA of the latest main commit**

```bash
SHORT_SHA=$(git rev-parse --short=7 main)
echo "verifying ghcr.io/setounkpe7/threat-intel-api:sha-${SHORT_SHA}"
```

- [ ] **Step 12.3: Run the three verification commands from `docs/RELEASING.md`**

```bash
IMAGE=ghcr.io/setounkpe7/threat-intel-api:sha-${SHORT_SHA}
IDENTITY_REGEX='^https://github\.com/Setounkpe7/threat-intel-api/\.github/workflows/release\.yml@refs/heads/main$'
OIDC_ISSUER=https://token.actions.githubusercontent.com

cosign verify "${IMAGE}" --certificate-identity-regexp "${IDENTITY_REGEX}" --certificate-oidc-issuer "${OIDC_ISSUER}"
cosign verify-attestation --type cyclonedx "${IMAGE}" --certificate-identity-regexp "${IDENTITY_REGEX}" --certificate-oidc-issuer "${OIDC_ISSUER}"
gh attestation verify oci://${IMAGE} --repo Setounkpe7/threat-intel-api
```

Expected: all three exit 0 and print verification details from Rekor / Sigstore. If any one fails, the PR has not delivered its claim — open a follow-up issue and consult the rollback section of `docs/RELEASING.md`.

- [ ] **Step 12.4: Mark the spec as delivered**

```bash
echo "Delivered: $(date -u +%Y-%m-%d)" >> docs/superpowers/specs/2026-05-28-sbom-cosign-design.md
git checkout -b chore/mark-cosign-spec-delivered
git add docs/superpowers/specs/2026-05-28-sbom-cosign-design.md
git commit -m "docs(spec): mark SBOM+cosign spec as delivered"
gh pr create --base dev --title "chore: mark SBOM+cosign spec as delivered" --body "Closes the loop after Phase B completed."
```

---

## Self-review

The following items in the spec were checked against the tasks above:

- **Goal 1 (publish to GHCR on merge to main):** Tasks 2, 3.
- **Goal 2 (CycloneDX SBOM via Trivy):** Task 4.
- **Goal 3 (cosign keyless OIDC signature):** Task 5.
- **Goal 4 (SBOM attached as in-toto attestation):** Task 5.
- **Goal 5 (SLSA L2 provenance):** Task 6.
- **Goal 6 (smoke verify in same job):** Task 6.
- **Goal 7 (SHA-pin third-party actions in security.yml):** Task 1.
- **Goal 8 (correct README + RELEASING.md + comm articles):** Tasks 7, 8, 9.
- **GHCR one-time setup:** Task 11.
- **Rollback procedures:** Task 7 (documented in RELEASING.md), Task 11.4 (live recovery).
- **Threat model:** documented in spec, referenced in RELEASING.md (Task 7).
- **Gitleaks README omission:** Task 8.1.

No placeholders remain. Where exact SHAs cannot be hard-coded (they are external API lookups that drift), each step provides the precise `gh api` command to fetch them. Action version numbers (e.g. `v4.2.2`) are stated as recommendations to look up the latest patch of, not as authoritative pins.
