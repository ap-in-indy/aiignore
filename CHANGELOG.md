# Changelog

All notable changes to the reference implementation and normative draft are
recorded here. The project follows Semantic Versioning for the npm package;
specification compatibility is identified separately by the `aiignore` field.

## [Unreleased]

## [0.1.0-alpha.1] - 2026-07-20

### Added

- Restricted-YAML `.aiignore.yaml` draft 0.1 specification and JSON Schema,
  with exact `.aiignore` reserved for existing gitignore-style compatibility.
- Deterministic file, environment, network, and string decision engine.
- Language-neutral conformance vectors, vector schema, report schema, and CLI
  runner.
- Language-neutral valid/invalid parser vectors, parser-vector schema, and CLI
  runner, plus an enumerated draft 0.1 coverage matrix.
- Codex permission-profile compiler, supplemental plugin hook, and provisional
  macOS sandbox result, refreshed against Codex 0.144.5 with an exact live plan.
- Gemini CLI context/settings compiler and supplemental extension hook,
  validated with Gemini CLI 0.50.0.
- Incident-derived recommended secret-protection profile and adversarial test
  beds.
- Canonical specification site, enterprise deployment profile, release
  workflow, SBOM/checksum/attestation assets, and package payload validation.
- Unscoped `aiignore` npm package identity exposing the CLI, TypeScript API,
  schemas, profiles, and portable conformance artifacts.
- Executable schema/runtime/vector coverage contract and expected-error
  decision vectors.
- OpenSSF Security Insights 2.2.0 metadata, an OSPS baseline self-assessment,
  and an executable production dependency-license policy.
- Content-addressed decision, parser, and live-harness test plans with canonical
  URIs, exact runner/report binding, and explicit report withdrawal semantics.
- A no-overwrite `aiignore init` command for the recommended profile.
- A cross-platform artifact gate that compares two independent packs, installs
  the tarball into a clean consumer project, exercises the npm binary and public
  exports, and compiles the declarations without ambient Node types.
- Deterministic policy-parser and decision-engine robustness fuzz targets with
  a checked-in dictionary, exact seed replay, per-change smoke coverage, and a
  weekly rotating-seed extended campaign.
- A schema-validated, versioned conformance manifest that binds the exact
  specification, schemas, portable vectors, and harness plan by canonical URI
  and SHA-256.
- A detached Ed25519 conformance-report envelope plus CLI/library signing and
  verification with mandatory out-of-band identity and public-key trust pins.
- Exact implementation-conformance reports and offline complete-bundle
  verification, separated from live harness-enforcement claims and signatures.
- Closed draft registries, an immutable errata index, and a release pipeline
  that separates dependency/build execution from OIDC and repository-write authority.
- Machine-audited public GitHub desired state covering no-bypass main/tag
  immutability, restricted tag creation, security features, workflow defaults,
  Pages, and release authority.
- Explicit single-maintainer alpha release authority with no independent human
  approval claim; administrator-bypass prevention, release-owner-only signed
  tag creation, and exact verified tagger identity remain enforced.
- Machine-validated normative traceability for all 16 specification sections
  and 151 BCP 14 keyword occurrences, with explicit external limitations.
- Executable witnesses for all 86 primitive policy-schema assertion sites, with
  traceability evidence anchored to the immutable release-tag source tree.
- Security architecture, compatibility/versioning, conformance-evidence,
  credential-management, collaborator-escalation, continuity, and alpha
  support/end-of-life policies suitable for external review.
- A control-level OpenSSF OSPS Baseline 2026.02.19 self-assessment that records
  evidence or an explicit gap for all 64 controls without claiming a badge.
- Verbatim DCO 1.1 plus a dedicated pull-request check that requires every
  commit sign-off to match its author name and email, using only the trusted
  base implementation and read-only pull-request metadata.
- Exact portable decision and secret-safe audit-event schemas, root-relative
  file-pattern semantics, and separate fail-closed adapter errors so malformed
  candidates cannot be misreported as policy-rule matches. Audit events are
  emitted only for containing operations that actually proceed.
- A secret-safe `aiignore doctor` readiness report and plain-language getting
  started path that distinguish policy validity, adapter translation, and
  externally established enforcement.
- A manifest-driven reference-conformance report that separates
  parser/decision interoperability from live harness enforcement, retains every
  failed case ID, and uses a distinct signed payload type.

### Fixed

- The trusted-base DCO workflow now supplies its read-only GitHub token under
  the exact environment name consumed by the validator, with mutation coverage
  preventing the runtime contract from drifting again.
- Release instructions consistently use the preferred maintainer and tagger
  identity `Alex <alex@alexdoes.it>`.
- Release attestation and CodeQL workflows now use verified, immutable upstream
  action commits, with policy regressions covering every CodeQL entry point.
- The release gate now enforces the documented tagger identity exactly as
  `Alex <alex@alexdoes.it>`.

### Security

- Fail-closed parsing, canonicalization, hook input limits, policy-digest
  pinning, and explicit adapter compilation-gap reports.
- Adversarial regressions for literal redaction replacement, wildcard IP
  rejection, port bounds/canonicalization, empty fragments, directory-self
  globs, network-path `?`, and secret-free regular-expression errors.
- Regressions for filename-format collision, Windows case aliases, BOM
  placement, encoded separators, zero-width redaction, output expansion,
  pinned external policy, hook input validation, and report provenance.
- Portable regressions for negated string-glob classes and malformed URL
  separator forms that standards-conforming URL parsers otherwise normalize.
- Deeply immutable loaded policies, race-resistant no-follow file loading,
  frozen string-redaction ordering, and rejection of authority text discarded
  by permissive URL parsers.
- Safe name-only environment diagnostics and complete Codex compilation gaps
  for default-deny environment and string policy.
- Platform-neutral public declarations using `Uint8Array` and ordinary records
  instead of undeclared `Buffer` and `NodeJS` ambient types.
- Terminal file and network `/**` patterns consume zero segments as required by
  the draft, so the base path and its descendants are both matched.
- Supplemental hooks preserve the event working directory for relative tool
  paths while evaluating against the independently pinned policy root.
- Supplemental hooks mediate bounded singular and plural path/URL fields,
  including array-valued bulk inputs, and conservatively classify common
  mutation and discovery tool aliases.
- Codex compilation reports a semantic-change gap instead of claiming exactness
  when its local/private destination defaults narrow network default allow.
- Policy and conformance-artifact reads enforce their byte ceiling during the
  read, reject symlinks and snapshot changes, and fail closed on an explicitly
  empty policy-digest pin or malformed hook-input UTF-8.
- Repository-owned, checksum-pinned Gitleaks scanning covers full Git history
  on pull requests, schedules, and releases without requiring a hosted-service
  security entitlement; repository configs, ignore files, environment
  overrides, and inline allow comments cannot suppress the release scan.
- Release publication now requires the signed tag to be reachable from `main`,
  binds the protected workflow dispatch ref to that exact tag,
  verifies every canonical site artifact byte-for-byte, attests checksums, and
  promotes the matching GitHub prerelease only after npm `alpha` succeeds;
  phase two cannot create or replace its inspected draft, CycloneDX output is
  normalized for reproducibility, title and notes are authenticated, and
  published-release reruns require a matching npm SHA-512 integrity value
  without requiring an obsolete global `alpha` dist-tag.
- The rotating-seed extended fuzz campaign now runs on every pull request so
  its required check cannot disappear behind path filters.
- Release workflow dispatch inputs are rejected unless they use a strict
  SemVer prerelease-tag grammar before the value reaches GitHub CLI or Git.
- Unpublished releases must advance monotonically beyond the current global
  npm `alpha` version, preventing an older signed tag from rolling the channel
  backward; `latest` must be empty or a stable version.
- Mutation-tested project-policy validation detects silent drift in release
  versions, DCO text, critical CODEOWNERS rules, structured issue intake,
  external-evidence claim language, and OSPS control accounting.

[Unreleased]: https://github.com/ap-in-indy/aiignore/compare/v0.1.0-alpha.1...HEAD
[0.1.0-alpha.1]: https://github.com/ap-in-indy/aiignore/releases/tag/v0.1.0-alpha.1
