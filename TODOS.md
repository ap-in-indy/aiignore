# TODOS

## Release administration

### Reserve and configure the npm package

**What:** Confirm control of `@apinindy/aiignore`, bootstrap the package if npm requires an initial manual publication, and configure the repository release workflow as its trusted publisher.

**Why:** Package-name availability is not ownership, and npm provenance is only produced for a public package built from a matching public repository.

**Context:** npm rejected the unscoped `aiignore` name as confusingly similar to `ignore`, so the approved release target is `@apinindy/aiignore`. The workflow requires npm 11.5.1+, OIDC trusted publishing, a protected `release` environment, and no long-lived publication token after bootstrap.

**Effort:** S
**Priority:** P0
**Depends on:** Public repository, npm maintainer account, explicit publication approval

### Activate public repository security controls

**What:** Enable GitHub Pages, private vulnerability reporting, branch/ruleset protection, required CI/CodeQL/dependency review, Discussions, secret scanning, and immutable releases.

**Why:** Workflows and community files cannot substitute for repository-side enforcement and reporting channels.

**Context:** Configure these controls immediately before or after the approved visibility change. Require signed commits or verified merge commits as appropriate, block force pushes and deletions on `main`, require the cross-platform CI, DCO, and security jobs, and restrict the `release` environment to reviewed `v*` tags without stored secrets.

The exact desired state is now versioned in `.github/hosting-policy.json` and
`npm run hosting:audit` verifies owner-side drift without mutation. The public
alpha deliberately uses transparent single-maintainer release authority;
activation and a clean live audit remain outstanding. Independent approval is
still required before advancing to candidate-standard maturity.

**Effort:** S
**Priority:** P0
**Depends on:** Implementation merged to `main`; explicit visibility approval

## Independent assurance

### Obtain an independent parser implementation

**What:** Have an unaffiliated team implement draft 0.1 from the specification and run all published parser and decision vectors.

**Why:** A reference implementation and its own vectors can share the same misunderstanding; independent running code is the strongest interoperability check.

**Context:** The coverage contract currently requires 107 decision vectors and 56 parser vectors. Record implementation language, source commit, vector SHA-256, failures, and ambiguous clauses. Do not advance to public-RFC maturity until at least two independent parsers agree.

**Effort:** L
**Priority:** P1
**Depends on:** Public canonical specification and vector URLs

### Commission independent security and threat-model review

**What:** Arrange an external assessment of parser safety, canonicalization, policy semantics, adapters, testbeds, and assurance claims.

**Why:** Self-review cannot establish that the model is safe or complete enough for candidate-standard or production security claims.

**Context:** Scope YAML handling, glob portability, URL normalization, Unicode/platform aliases, string-filter denial of service, policy integrity, hook bypasses, permission-profile compilation, network/DNS behavior, archives/provenance, and report verification. Publish findings and remediation unless coordinated disclosure is required.

**Effort:** L
**Priority:** P1
**Depends on:** Public draft release and stable review commit

### Expand live sandbox evidence

**What:** Run versioned no-model and model-driven conformance on Linux, WSL2, native Windows, and supported macOS architectures.

**Why:** Filesystem aliases, glob expansion, case behavior, symlinks, process inheritance, and network enforcement differ materially by backend.

**Context:** The current live result covers Codex 0.144.x on macOS Seatbelt and intentionally records archive provenance as a failure. Add clean-source reports with runner/vector hashes, exact OS builds, false/negative cases, and detached verification material.

**Effort:** L
**Priority:** P1
**Depends on:** Access to representative systems and exact supported harness versions

## Specification evolution

### Standardize monotonic administrator-policy composition

**What:** Define and implement a composition algebra in which repository policy cannot weaken administrator policy.

**Why:** Enterprise deployments eventually need organization baselines plus repository-specific restrictions without ambiguous priority or redaction behavior.

**Context:** Draft 0.1 deliberately uses one explicit policy. An RFC must define per-resource effect ordering, defaults, exceptions, policy provenance in decisions, combined digests, string-redaction composition, adapter compilation, and failure behavior before any multi-policy API is added.

**Effort:** XL
**Priority:** P2
**Depends on:** RFC review and independent implementer feedback

### Adopt a standards IPR and trademark policy

**What:** Select an explicit standards-essential patent, contribution, and conformance-mark policy with legal review.

**Why:** MIT plus DCO does not provide all assurances expected from a mature multi-vendor standard.

**Context:** `docs/intellectual-property.md` records the current limitation. Evaluate Apache-2.0 or a foundation/standards-process policy, contributor patent commitments, trademark ownership, certification wording, and neutral stewardship before candidate-standard status.

**Effort:** M
**Priority:** P1
**Depends on:** Legal counsel, contributor consultation, and neutral-governance direction

### Add independent harness adapters

**What:** Add adapters and live reports for Qwen Code, OpenHands, Cursor, and generic MCP/tool gateways.

**Why:** A harness-neutral proposal needs implementation experience beyond the two initial adapters and must confront browser, app, MCP, and remote-tool boundaries.

**Context:** Each adapter must map all tool paths, refuse exact-conformance claims when translation is lossy, pin a tested version, and publish explicit gaps. Coordinate with upstream maintainers rather than inferring private contracts.

**Effort:** XL
**Priority:** P2
**Depends on:** Public RFC feedback and upstream collaboration

## Completed

### Establish release-signing identity

Alex's dedicated SSH release-signing key is registered with GitHub as
`aiignore`, configured locally for signed tags only, and documented with
rotation and revocation guidance in `docs/credential-management.md`. Its
fingerprint is
`SHA256:+EVeNek6l+BBNWIwJQiJNmzHVzUxnuiydPmKYDDWoxw`. A disposable annotated
tag on the reviewed commit was signed and independently verified with Git,
then deleted locally without being pushed.

**Completed:** v0.1.0-alpha.1 (2026-07-17)

### Ship a signed conformance-report format and verifier

Draft 0.1 now defines a detached Ed25519 envelope, exact domain-separated
signature bytes, a report/envelope cross-binding contract, and CLI/library
signing and verification. Verification requires an identity and SPKI DER
SHA-256 supplied through an independent trusted channel and rejects report,
signature, identity, issuer, and key substitution. Production signer identity,
key custody, rotation, and revocation remain deployment responsibilities.
