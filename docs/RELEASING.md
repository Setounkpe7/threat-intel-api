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
