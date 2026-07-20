# Dependency-management policy

The reference implementation minimizes production dependencies and treats every
dependency change as a supply-chain and compatibility change.

## Required checks

1. Use the committed `package-lock.json`; CI installs with
   `npm ci --ignore-scripts`.
2. Review direct and transitive additions, lifecycle scripts, maintainers,
   release provenance, package age, and download source before acceptance.
3. Keep runtime packages on SPDX-identified permissive licenses approved by
   `scripts/validate-licenses.mjs`. A new license requires explicit maintainer
   review and a policy update; an unknown license fails CI.
4. Run `npm audit --omit=dev --audit-level=low`, `npm audit signatures`, the
   complete test suite, package-payload validation, two-pack byte
   reproducibility, and a clean consumer install/type/runtime smoke test on
   every release candidate. Run the deterministic fuzz smoke gate on every
   change and inspect the latest rotating-seed extended campaign before release.
5. Pin GitHub Actions to full commit SHAs. Dependabot may propose updates, but a
   human must review the upstream release and immutable commit before merging.
6. Do not add long-lived package-registry credentials. npm publication uses a
   repository-bound OIDC trusted publisher after the public package is
   bootstrapped.

## Vulnerability handling

A production vulnerability is a release blocker unless the maintainer records
why the affected code is unreachable, what compensating control applies, and
when the dependency will be removed or updated. Security fixes follow
`SECURITY.md`; do not discuss an exploitable unpublished issue in a public
dependency-update pull request.

Development-only findings are triaged by exploitability and exposure rather
than hidden. Build-time packages can still compromise release artifacts, so the
release workflow verifies registry signatures and creates artifacts only on a
GitHub-hosted runner from a signed tag.

## Generated evidence

Each release includes a CycloneDX SBOM, SHA-256 checksums, and GitHub artifact
attestations. These prove artifact identity and build provenance; they do not
prove that the policy semantics or a harness integration are secure.
