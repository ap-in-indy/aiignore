# Alpha release checklist

Publication has three independent gates. Passing one does not authorize or
imply the next.

## 1. Push to the private GitHub repository

- [x] Work is committed on a feature branch with DCO sign-off.
- [x] The DCO validator validates every current feature-branch commit against
      its author name/email; the trusted-base required check applies to
      subsequent pull requests after this workflow reaches `main`.
- [x] `npm run verify` passes from a clean checkout.
- [x] GitHub Actions passes on Node 20/24 across Linux, macOS, and Windows for
      the exact current candidate commit.
- [x] The npm dry-run contains the specification, schemas, vectors, profiles,
      and both harness integrations.
- [x] `npm audit --omit=dev` reports no known production vulnerabilities.
- [x] The deterministic parser/decision fuzz smoke campaign passes.
- [x] A checksum-pinned Gitleaks scan covers every reachable commit locally and
      in the repository-owned pull-request workflow.

This gate is incomplete until the exact current candidate passes every hosted
check. Any new commit invalidates prior hosted evidence; checkmarks are evidence
of the gate, not authorization for public visibility or publication.

## 2. Change repository visibility to public

- [ ] A maintainer explicitly approves the visibility change.
- [ ] `SECURITY.md`, private vulnerability reporting, issue templates, DCO, and
      governance documents are visible and correct.
- [ ] No fixture, Git object, workflow log, or conformance artifact contains a
      real credential, internal hostname, personal path, or private transcript.
- [ ] `security-insights.yml` validates against the OpenSSF Security Insights
      2.2.0 CUE schema and its canonical URL is publicly readable.
- [ ] Alpha limitations are prominent in the README and adapter guides.
- [ ] Every canonical specification, schema, vector, checksum, and
      `security.txt` URL returns the reviewed artifact over HTTPS.
- [ ] The canonical conformance manifest validates and every listed SHA-256
      matches the public bytes.
- [ ] Repository and package descriptions say “experimental specification,”
      not “industry standard” or a security guarantee.
- [ ] A `main` ruleset requires pull requests, conversation resolution,
      cross-platform CI, package, DCO, fuzz, dependency-review, CodeQL, and
      full-history Gitleaks checks while blocking force pushes and deletion;
      human approval count is explicitly zero for the single-maintainer alpha.
- [ ] A no-bypass `v*` tag ruleset blocks release-tag update and deletion; a
      separate rule restricts creation to the documented release owner; and the
      `release` environment has no human-review rule, disables administrator
      bypass, stores no secrets or variables, and restricts deployments to `v*`.
- [ ] GitHub-native secret scanning, push protection, private vulnerability
      reporting, dependency alerts, and CodeQL are enabled.
- [ ] `npm run hosting:audit` returns zero against the reviewed
      `.github/hosting-policy.json` desired state.
- [ ] The initial tag is signed and points to the reviewed commit.

## 3. Publish `aiignore`

- [ ] The unscoped package name remains available and the maintainer account
      is authorized to publish it.
- [ ] A tag-triggered release workflow uses npm trusted publishing/provenance;
      no long-lived npm token is stored when OIDC is available.
- [ ] The npm trusted publisher is restricted to this repository, the
      `release.yml` workflow, the `release` environment, and the `npm publish`
      action.
- [ ] The package tarball is reproduced from the tagged clean checkout.
- [ ] The packaged conformance manifest binds the reviewed specification,
      registry/errata companions, schemas, vector packs, and harness plan
      without membership or digest drift.
- [ ] The committed artifact validator produces two identical tarballs, installs
      one in a clean project, exercises npm-bin `init`/`validate`, imports every
      public artifact family, and type-checks without ambient `@types/node`.
- [ ] Production dependency licenses pass the committed allowlist and the SBOM
      contains license metadata for every shipped dependency.
- [ ] The latest scheduled extended fuzz campaign passes and any reduced
      crashers have been promoted to reviewed regression vectors or tests.
- [ ] The release workflow proves the signed tag is reachable from `main` and
      every canonical Pages artifact matches the reviewed build byte for byte.
- [ ] Release assets include SHA-256 checksums, a CycloneDX SBOM, and a GitHub
      artifact attestation; consumers can verify each artifact.
- [ ] The release run proves the build job has no OIDC/write authority and the
      protected job accepts only the reviewed inert inventory and pinned npm CLI.
- [ ] `CHANGELOG.md` contains the released version and date.
- [ ] The GitHub release links the exact spec, schemas, vector revision, known
      gaps, and checksums.
- [ ] A publication-enabled run promotes the matching GitHub prerelease only
      after npm `alpha` publication and verifies that `latest` was not changed.

## Gates intentionally deferred for a candidate standard

- Independent parser implementation.
- Independent security assessment.
- Linux, WSL2, and native Windows live sandbox conformance.
- Neutral multi-organization governance.
