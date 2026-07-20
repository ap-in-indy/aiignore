# Project credential and signing-key policy

This policy covers credentials used to administer the repository, CI/CD,
package registry, release signing, canonical site, vulnerability reporting,
and conformance-report signing. It does not claim that owner-controlled hosting
settings are active until they are independently verified.

## Baseline requirements

- Require phishing-resistant multi-factor authentication where the service
  supports it. Recovery methods must not be weaker shared credentials.
- Grant collaborators the lowest role needed and review every escalation before
  access to repository settings, environments, advisories, package ownership,
  signing keys, or trusted-publisher configuration.
- Use short-lived, audience-bound OIDC credentials for automation. Do not store
  long-lived npm publication tokens in GitHub, local configuration, or workflow
  files.
- Keep human account recovery material, release-signing private keys, and
  conformance-signing private keys outside the repository and CI artifacts.
- Use distinct keys or identities for Git release tags and conformance reports;
  one compromised purpose must not silently authorize the other.
- Never place production credentials, customer data, private policies, or live
  tokens in tests, issues, discussions, logs, screenshots, or support bundles.

## Release authority

The npm trusted publisher must bind the exact public repository,
`.github/workflows/release.yml`, and protected `release` environment. The
workflow receives `id-token: write` only for the release job and publishes from
a GitHub-hosted runner after signed-tag verification. Dependency installation,
tests, package construction, SBOM generation, and secret scanning run first in
a separate job with read-only repository access and no protected environment,
OIDC, attestation, or repository-write authority. The protected job accepts
only an exact artifact inventory, re-verifies release checksums, and executes a
SHA-512-pinned npm CLI transferred from the unprivileged job. Traditional automation
tokens are revoked or disabled after bootstrap.

The public alpha has one release authority. Publication therefore has no
independent human approval gate: the maintainer who creates the signed tag may
also dispatch the release. Compensating controls are an owner-only tag-creation
rule, exact verified tag identity, `main` ancestry, required automated checks,
two-phase byte equality, a tag-restricted environment with administrator bypass
disabled, OIDC trusted publishing, attestations, and no stored release secrets.
This is explicit risk acceptance for the alpha, not two-person review.

Release tags use a GitHub-verified annotated signature from a documented
maintainer identity. The release gate also requires the exact tagger identity
`Alex <alex@alexdoes.it>`, GitHub's `valid` verification reason, and
the release-specific tag message. Key fingerprints and verification
instructions are published through a channel separate from the release asset.
Rotation creates a new identity record; old verified tags remain attributable
to their original key.

### Active release-tag signing identity

The active release-tag signer from 2026-07-17 is:

- tagger: `Alex <alex@alexdoes.it>`;
- GitHub account: `ap-in-indy`;
- GitHub signing-key title: `aiignore`;
- algorithm: Ed25519;
- SSH SHA-256 fingerprint:
  `SHA256:+EVeNek6l+BBNWIwJQiJNmzHVzUxnuiydPmKYDDWoxw`; and
- public key:
  `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB39xnm8+2oeo+9rsz6RkmTmy9x3Nxpr9vF3dkt1n8hI`.

This key authorizes annotated Git release tags only. It does not authorize
conformance-report signatures, npm publication by itself, commits, policy
changes, or a claim of independent review. The private key is maintainer-held
and is not stored in the repository or GitHub Actions.

To verify a fetched release tag without trusting the repository's local Git
configuration, create a temporary allowed-signers file from the independently
obtained key above:

```sh
ALLOWED_SIGNERS=$(mktemp)
printf '%s\n' \
  'alex@alexdoes.it ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB39xnm8+2oeo+9rsz6RkmTmy9x3Nxpr9vF3dkt1n8hI' \
  > "$ALLOWED_SIGNERS"
git -c gpg.ssh.allowedSignersFile="$ALLOWED_SIGNERS" verify-tag v0.1.0-alpha.1
rm -f "$ALLOWED_SIGNERS"
```

Verification must report a good SSH signature for `alex@alexdoes.it`, the tag
must remain reachable from the reviewed `main` history, and GitHub must report
the annotated tag object's signature as `verified` with reason `valid`.
Fingerprint comparison is an independent trust step; a green GitHub badge
alone does not replace it.

If this key is rotated, append the replacement identity and activation date
here rather than overwriting this record. If it is compromised, mark it revoked
with the earliest affected time, remove it from GitHub, halt publication, and
follow the incident procedure below without rewriting existing tags.

## Conformance signing

Conformance private keys are supplied only to an explicit offline or protected
signing operation. Reports carry a public key, but verifiers trust only the
expected identity and SPKI SHA-256 obtained outside the report/envelope pair.
Signer rotation and revocation follow `docs/conformance-signatures.md`.

## Detection and prevention

The required repository scan uses a checksum-pinned Gitleaks binary, scans all
reachable revisions as text, and disables repository configuration, ignore
files, environment overrides, text-conversion attributes, and inline allow
comments. GitHub-native secret scanning and push protection are additional
public-hosting controls, not substitutes for the repository-owned scan.

Synthetic credential patterns used in regression tests must be assembled at
runtime or otherwise be unmistakably nonfunctional. Tests may not suppress the
required release scan.

## Rotation and incident response

Rotate or revoke a credential immediately when it may have appeared in source,
history, logs, an artifact, an issue, a transcript, or an untrusted process.
Deleting the visible value is not remediation. Preserve evidence needed for
incident analysis without redistributing the credential.

For a compromised release or conformance key:

1. revoke or remove the key from the authoritative account/channel;
2. stop releases and announcements;
3. identify every affected tag, package, report, and attestation;
4. publish a security notice and withdrawal/supersession record;
5. establish a new independently communicated trust pin;
6. release a new version—never rewrite a tag or package version.

Access and key records are reviewed before every release and at least annually
while the project is active. A single-maintainer project cannot provide
two-person key custody; that limitation remains explicit until another trusted
maintainer is added.
