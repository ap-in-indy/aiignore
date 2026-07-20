# Draft 0.1 test coverage matrix

This matrix is the release checklist for language and reference-engine
behavior. “Portable” means another implementation can consume the JSON vector
without using the TypeScript test suite.

| Surface | Enumerated cases | Portable evidence | Reference evidence |
| --- | --- | --- | --- |
| Document syntax | Minimal/full documents, metadata, defaults, all rule families, BOM, CRLF | Parser vectors | `parser.test.ts` |
| YAML restrictions | Duplicate keys, multiple documents, anchors, aliases, tags, merge keys, non-string keys | Parser vectors | `parser.test.ts` |
| Schema constraints | All 86 declared primitive assertion sites: types, version, unknown fields, required fields, ids, every enum, integer/scalar/array bounds, uniqueness, and conditional replacement placement; unsupported or unwitnessed Draft 2020-12 keywords fail | Parser vectors and JSON Schema | `parser.test.ts`, `policy-schema-contract.test.ts` |
| File globs | `*`, `?`, double-star segment positions, classes, leading/trailing slash, dotfiles, exceptions, forbidden constructs | Decision/parser vectors | `patterns.test.ts`, `engine-file.test.ts` |
| File operations/effects | discover, index, read, write, execute; allow, deny, audit, read-only; default allow/deny | Decision vectors | `engine-file.test.ts` |
| Environment | `*`, `?`, classes, case behavior, exceptions; allow, deny, drop, redact, audit; default allow/deny | Decision/parser vectors | `engine-environment.test.ts` |
| Network | http/https/ws/wss, exact/`*.`/`**.` hosts, IDNA, IPv4/IPv6, ports 0–65535, paths, query exclusion, fragments/userinfo rejection | Decision/parser vectors | `patterns.test.ts`, `engine-network.test.ts` |
| Strings | literal/glob/RE2, case sensitivity, all 11 scopes, exceptions, allow/deny/redact/audit, literal replacements, composition | Decision/parser vectors | `engine-string.test.ts`, `patterns.test.ts` |
| Selection | priority, later-rule tie breaking, rule-local exceptions, resource defaults | Decision vectors | Engine tests |
| Decision and audit protocol | exact resource/effect-specific decision shape, default null pairing, output/appliedRuleIds constraints, reason presence, policy digest, secret-safe audit event | Decision/audit JSON Schemas, options vectors, runner invariants | `protocol-schema.test.ts`, engine and CLI tests |
| CLI | help/version, validate, check, scan, filter-env, run, compile, hooks, portable runners, reference report generation, offline implementation-report verification, exit/error paths | CLI invokes portable runners | `cli.test.ts` |
| Operator readiness | resolved defaults, rule/control counts, adapter gap counts, fixed non-enforcement claim, fixed findings, secret/path/pattern omission | Readiness-report JSON Schema | `readiness.test.ts`, `cli.test.ts` |
| File-input integrity | regular-file identity, no-follow symlink rejection, exact byte limits, growth bounds, snapshot consistency, fatal UTF-8 decoding | Manifest and runner diagnostics | `safe-file.test.ts`, parser/runner tests |
| Codex/Gemini adapters | exact/partial compilation, explicit gaps, structured file/network/env/string hook mediation, malformed input fail-closed | Harness reports/testbeds | Adapter tests |
| Live harness provenance | exact test-plan URI/revision/SHA-256, runner SHA-256, unique case IDs, report withdrawal semantics | Harness vectors and report schema | `harness-vectors.test.ts`, Codex live runner |
| Detached report verification | report/envelope schemas, exact-byte SHA-256, Ed25519 domain separation, pinned identity/issuer/key, tamper and substitution rejection, no-overwrite signing | Signature-envelope schema | `report-signature.test.ts`, `cli.test.ts` |
| Coverage contract | schema/runtime enum parity, all observable effects, operations, scopes, and normative diagnostics | All portable vectors | `coverage-contract.test.ts` |
| Normative traceability | all 16 top-level specification sections, 151 BCP 14 keyword occurrences, assurance classification, checked-in evidence paths, and non-removable external limitations | Versioned machine-readable requirements catalog | `requirements-v0.1.json`, `requirements-traceability.test.ts`, `validate-requirements-traceability.mjs` |
| Versioned conformance bundle | exact artifact membership, canonical URI, media role, package version, regular-file identity, and SHA-256 for specification, schemas, requirements traceability, and vectors | Published manifest and canonical-site checksums | `conformance/manifest-v0.1.json`, `validate-conformance-manifest.mjs` |
| Implementation evidence | complete manifest-selected parser/decision suite execution, offline manifest-membership verification, omission/identity rejection, source/runner identity, summary arithmetic, failed-ID retention, claim separation, signature domain separation | Implementation-report JSON Schema and manifest | `implementation-conformance.test.ts`, `report-signature.test.ts`, `cli.test.ts` |
| Robustness fuzzing | mutated policy bytes, stable error taxonomy, digest/immutability/determinism invariants, Unicode and malformed candidates, prototype-property environment records | Weekly rotating-seed extended campaign | `test/fuzz/fuzz.mjs`, `test/fuzz/aiignore.dict` |
| Project maturity policy | package/language/vector version separation, closed registries and immutable errata, author-matching DCO sign-off, sensitive-path ownership, structured intake, credential/conformance/support contracts, and all 64 structured OSPS 2026.02.19 control records | Trusted-base DCO check and self-assessment | `validate-dco.mjs`, `validate-project-policy.mjs`, `dco.test.ts`, `project-policy.test.ts` |
| Public hosting policy | exact repository settings, no-bypass main/immutable-tag rulesets, release-owner-only tag creation, ten required checks pinned to GitHub Actions, code-scanning thresholds, explicitly solo tag-restricted release environment, empty secret/variable stores, semantic order tolerance, exact drift and unavailable-evidence failure | Versioned GitHub desired state and read-only API audit | `github-hosting-audit.test.ts`, `audit-github-hosting.mjs`, `hosting-policy.json` |
| Distribution | executable npm-bin CLI, required schemas/vectors/docs, forbidden development files, package-size cap, canonical site IDs, two-pack byte reproducibility, clean install, public runtime exports, ambient-type-free TypeScript consumption, suppression-resistant full-history secret scanning, mutation-tested workflow gates, strict release-tag input, monotonic alpha channel, reproducible SBOM identity, and bounded exact remote publication bytes | Release workflow and checksums | `validate-package.mjs`, `validate-artifact.mjs`, `build-site.mjs`, `normalize-sbom.mjs`, `validate-alpha-advance.mjs`, `verify-publication.mjs`, `alpha-advance.test.ts`, `publication.test.ts`, `sbom.test.ts`, `workflow-policy.test.ts` |

## Release rule

A draft release MUST pass `npm run verify`. Coverage includes every executable
file under `src/` and MUST meet 95% statements, 86% branches, 99% functions,
and 96% lines. New syntax or an option is incomplete until this matrix, the
normative specification, and at least one portable vector are updated. Every
primitive assertion keyword added to the policy schema also requires an
executable boundary witness; the schema-aware contract rejects unsupported
keywords and unreviewed assertion sites.

This matrix does not turn an adapter into an OS sandbox. End-to-end enforcement
claims require the separate harness evidence listed in
`docs/research/adversarial-test-results.md`.
