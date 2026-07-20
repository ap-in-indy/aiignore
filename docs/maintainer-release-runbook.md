# Maintainer release runbook

This runbook turns a reviewed commit into a public alpha. It is deliberately
separate from the automated release workflow: completing a technical gate does
not authorize a merge, visibility change, tag, GitHub release, or npm publish.

The first public release uses two phases. Phase one builds an inspectable draft
without publishing npm. Phase two repeats every gate, publishes the identical
package through npm trusted publishing, and promotes the matching GitHub
prerelease. Never skip phase one.

## 1. Protect the repository

After the initial pull request is merged and the repository is public, run one
bootstrap pull request through every check listed below. GitHub only permits a
check to become required after it has completed successfully in the repository
during the preceding seven days. Before inviting contributors, configure a
GitHub ruleset for `main`:

- require changes through a pull request and zero human approvals while the
  project has one maintainer;
- require resolved conversations;
- block force pushes and branch deletion;
- apply the rules to administrators, with no routine bypass actor;
- require these checks:
  - `Node 20 on ubuntu-latest`;
  - `Node 24 on ubuntu-latest`;
  - `Node 24 on macos-latest`;
  - `Node 24 on windows-latest`;
  - `package`;
  - `DCO sign-off`;
  - `fuzz`;
  - `Gitleaks full history`;
  - `dependency-review`; and
  - `Analyze JavaScript and TypeScript`.

Create a no-bypass tag ruleset for `v*` that blocks tag update and deletion.
Use a separate creation ruleset whose only bypass is the documented release
owner's stable GitHub user ID; no other write collaborator may reserve a
release tag. The release workflow also
rejects lightweight tags, unverified signatures, tags not reachable from
`main`, version disagreement, and missing release notes.

Enable GitHub-native secret scanning, push protection, dependency graph,
Dependabot alerts and updates, CodeQL, private vulnerability reporting, and
OpenSSF Scorecard after the repository is public. The repository-owned
Gitleaks workflow remains required because it scans every reachable commit in
private and public repositories without depending on a GitHub plan.

The exact desired state and read-only verification procedure live in
`.github/hosting-policy.json` and `docs/public-hosting.md`. Run
`npm run hosting:audit` after configuration, before tagging, and after any
owner-side settings change. A checklist review is not a substitute for a clean
machine audit.

## 2. Protect release authority

Create a GitHub environment named `release`:

- configure no required-reviewer rule and make no independent-approval claim;
- disallow administrator bypass of environment restrictions;
- restrict deployment to protected release tags matching `v*`;
- do not store npm tokens or signing private keys in the environment; and
- retain the deployment history.

The same maintainer may create the signed tag and dispatch both release phases.
This accepted alpha risk is recorded in `MAINTAINERS.md`, the security baseline,
and release notes. Do not describe it as peer-reviewed release authorization.
When a second trusted maintainer is added, update the versioned hosting policy
and require non-author review before advancing project maturity.

Configure npm trusted publishing for:

- package: `aiignore`;
- repository: `ap-in-indy/aiignore`;
- workflow: `.github/workflows/release.yml`; and
- environment: `release`.

Require phishing-resistant MFA on the maintainer's GitHub and npm accounts.
Keep recovery codes outside the development machine. Treat a compromised
maintainer account as a release-key compromise even when OIDC is used.

## 3. Configure a verified tag signer

Use a GitHub-supported GPG, SSH, or S/MIME signing key whose private half is not
stored in the repository. Upload only the public signing key to GitHub, then
configure Git to use it. Verify the configuration with a disposable signed tag
before creating a release tag.

The release command is intentionally ordinary Git; `-s` requests the configured
cryptographic signer and `-a` ensures an annotated tag object exists:

```sh
VERSION=0.1.0-alpha.1
git switch main
git pull --ff-only
git status --short
npm ci --ignore-scripts
npm run verify
npm run security:secrets
git tag -s -a "v$VERSION" -m "aiignore policy $VERSION"
git verify-tag "v$VERSION"
git push origin "v$VERSION"
```

Confirm that GitHub marks the tag object as verified before dispatching the
release. The workflow also requires GitHub's `valid` reason, the exact tagger
identity `Alex <alex@alexdoes.it>`, and the message
`aiignore policy VERSION`. DCO sign-off and cryptographic tag signing are
different controls; the project requires both.

## 4. Build the inspectable draft

Run the release workflow with publication disabled:

```sh
gh workflow run release.yml \
  --ref v0.1.0-alpha.1 \
  -f tag=v0.1.0-alpha.1 \
  -f publish_npm=false
```

The workflow must:

1. prove the dispatch ref equals the requested annotated tag, the repository is
   public, and the tag is GitHub-verified;
2. prove the tagged commit is reachable from `main` and matches every version;
3. run the complete test, conformance, fuzz-smoke, package, license, workflow,
   and security-metadata gates;
4. rescan all reachable Git history with checksum-pinned Gitleaks;
5. compare every canonical GitHub Pages artifact byte-for-byte with the
   reviewed site build;
6. create two identical npm packs and test a clean installed consumer;
7. generate the tarball, CycloneDX SBOM, and SHA-256 file in a read-only,
   unprivileged build job;
8. transfer only those inert assets plus a SHA-512-pinned npm CLI to the
   protected release job, re-verify the exact file inventory and every digest,
   and execute no dependency installation, build, or test command there;
9. create or verify the draft GitHub prerelease and prove phase-two bytes match
   the previously inspected normalized assets;
10. attest all three verified release assets before any npm publication; and
11. publish only after the preceding identity, equality, and attestation gates.

Download the draft assets to a clean directory. Verify `SHA256SUMS`, inspect the
SBOM, install the tarball into a disposable project with `--ignore-scripts`, and
run `aiignore --version`, `aiignore init`, and `aiignore validate`. Compare the
tarball SHA-256 with the workflow's package-validation output.

## 5. Publish the alpha

Only after the draft inspection passes, dispatch the identical workflow with
publication enabled:

```sh
gh workflow run release.yml \
  --ref v0.1.0-alpha.1 \
  -f tag=v0.1.0-alpha.1 \
  -f publish_npm=true
```

This second run repeats all gates, refuses to create or replace the inspected
draft, and proves its rebuilt tarball, normalized SBOM, and checksums are
byte-identical to the draft assets. It publishes with the `alpha` npm dist-tag,
proves the draft title and body match the tagged release notes, proves that
`latest` does not point to the prerelease, rechecks the metadata and assets,
then publishes the matching GitHub prerelease. A rerun never mutates an
immutable published release: it continues only when the existing GitHub assets
and already-published npm package are byte-identical to the rebuilt candidate;
verification of an older immutable alpha does not move the current `alpha`
dist-tag backward. Because GitHub Pages represents the current `main` build and
is intentionally mutable, an already-published historical rerun skips the Pages
comparison and relies on the immutable release assets plus npm SHA-512
integrity. New and draft releases may never skip the Pages comparison.

Verify the public result independently:

```sh
npm view @apinindy/aiignore@0.1.0-alpha.1 version dist.integrity
npm view @apinindy/aiignore dist-tags --json
gh release view v0.1.0-alpha.1 --json isDraft,isPrerelease,assets
gh release download v0.1.0-alpha.1 --dir release-verification
gh attestation verify \
  release-verification/apinindy-aiignore-0.1.0-alpha.1.tgz \
  --repo ap-in-indy/aiignore
npm run publication:verify
```

Also verify the public `security.txt`, specification, schemas, vectors, and
conformance manifest from a network that is not authenticated to GitHub. Do not
announce until installation from npm and every canonical link work anonymously.

## 6. Respond to a bad release

Do not overwrite a tag or published package version. Stop announcements,
withdraw affected conformance reports, mark the GitHub release and npm version
as affected, rotate any exposed credential or signing authority, and publish a
new patched prerelease after completing this runbook again. Preserve a public
incident record unless doing so would disclose an unpatched vulnerability.
