# Security architecture and external interfaces

This document inventories actors, components, trust boundaries, and externally
observable interfaces for the draft 0.1 reference implementation. The
normative semantics remain in `spec/aiignore.md`.

## Actors and trust assumptions

| Actor | Trusted for | Not trusted for |
| --- | --- | --- |
| Organization administrator | external policy, digest, sandbox, egress, audit sink | repository-authored exceptions unless explicitly reviewed |
| Repository author | developer policy and project content | weakening administrator controls or changing protected launch assets |
| Harness operator | choosing exact harness/backend and accepting scoped residual risk | inferring untested conformance |
| Harness/model/subprocess | no security decision | policy integrity, access authorization, or truthful self-restraint |
| Adapter | faithful mediation of documented interfaces | paths it does not enumerate or cannot enforce |
| Reference CLI/library | parsing, canonical decisions, report operations | installing an OS sandbox or proving complete harness mediation |
| Conformance signer | authenticity of exact report bytes | correctness beyond the signer's reviewed process |
| Release workflow | reproducible packaging and publication binding | semantic security merely from provenance |

Repository content, model output, dependencies, tool arguments, URLs, DNS,
archives, Git history, logs, and remote services are untrusted inputs.

## Components and data flow

```text
bounded policy bytes
  -> restricted YAML parser -> JSON Schema -> semantic validators
  -> immutable policy + exact-byte digest
  -> canonical candidate -> deterministic decision engine
  -> CLI / adapter compilation / hook decision
  -> external sandbox, egress control, or harness enforcement
  -> candidate-free audit event and versioned conformance evidence
```

Parsing and decisions are in-process library functions. The CLI exposes them as
commands. Adapters translate or mediate vendor interfaces and must report every
semantic gap. Filesystem and network isolation remain external enforcement
components.

## Public TypeScript interface

The `aiignore` root export provides:

- policy parsing and validation;
- `PolicyEngine` decisions for files, environment names/values, networks, and
  string scopes;
- exact portable decision/audit schemas, validators, and secret-safe audit
  event construction;
- Codex and Gemini compilation/report types;
- decision and parser conformance runners;
- complete manifest-driven implementation-conformance reports;
- conformance-report signing and verification;
- version constants, enums, schemas, and public data types.

Package subpath exports provide the versioned schemas, manifest, portable
vectors, recommended profile, and live Codex harness plan. Package validation
installs the packed tarball in a clean consumer and executes both runtime and
ambient-type-free TypeScript checks.

## CLI interface

The `aiignore` executable exposes `init`, `validate`, secret-safe `doctor`,
resource `check`, `scan`, `filter-env`, `run`, adapter `compile`, both
conformance runners, complete implementation-report generation, and report
sign/verify operations. Decisions use the exact portable JSON Schema when
`--json` is selected; enforcement errors remain separate from rule decisions.
Exit classes distinguish allow/audit, deny/drop, invalid input, and partial
adapter export.

`doctor` reports resolved defaults, control counts, and adapter gap counts but
never policy source paths, patterns, rule IDs, candidate values, or detailed gap
messages. Its deployment-enforcement field is structurally fixed to
`not-established`; it cannot turn static inspection into an enforcement claim.

`run` filters inherited environment variables and pins control-plane path,
root, and digest variables before launching a child. It does not install file
or network isolation.

## File and process interfaces

- `.aiignore.yaml` is the one structured repository policy for draft 0.1.
- exact `.aiignore` remains reserved for existing gitignore-style tools.
- policy, vector, report, key, and envelope reads are bounded, fatal UTF-8, and
  no-follow where identity matters.
- standard input carries string scan input, environment-name/value records, or
  hook event JSON depending on the command.
- standard output carries decisions or compiled artifacts; standard error
  carries versioned candidate-free audit events and diagnostics that avoid
  secret-bearing pattern/value excerpts.
- child processes inherit only the filtered environment but require an
  external sandbox for file/network isolation.

## Adapter interfaces

The Codex integration emits a permission profile and supplies a supplemental
pre-tool hook. The Gemini integration emits a generated context-ignore file,
settings fragment, and `BeforeTool` hook. Both pin an external policy path,
workspace root, and digest in high-assurance launch mode. Both are explicitly
partial where the vendor interface cannot represent normative semantics.

MCP servers, apps, browser automation, remote tools, shell subprocesses,
archives, caches, diagnostics, redirects, and DNS are separate attack paths.
They are not covered merely because a direct adapter hook exists.

## Distribution and update interfaces

- GitHub is the source, issue, advisory, release, and attestation authority.
- GitHub Pages serves canonical specification/schema/vector bytes after a
  `main`-only build.
- npm distributes `aiignore` through OIDC trusted publishing.
- release assets include the package tarball, normalized CycloneDX SBOM, and
  `SHA256SUMS`, each covered by GitHub artifact attestation.

The release workflow constructs and verifies those assets in a job with
read-only repository access and no protected environment, OIDC, attestation,
or repository-write authority. A protected dependent job accepts only the
expected inert file inventory, re-verifies release digests and the pinned npm
CLI integrity, then performs attestation and publication without installing
dependencies or rebuilding source.

Mutable distribution locations are authenticated by exact checksums or package
integrity. Historical releases never depend on the current mutable Pages
snapshot.

Owner-controlled GitHub rulesets, security features, workflow defaults, Pages,
immutable releases, and the tag-restricted release environment are a separate
hosting boundary. `.github/hosting-policy.json` defines their exact desired
state, and `scripts/audit-github-hosting.mjs` reads GitHub APIs without mutating
settings or exposing environment secret names.

## Security boundaries and failure modes

The parser and decision engine fail closed on malformed, ambiguous, oversized,
or unsupported inputs. An adapter compilation error or error-severity gap
invalidates an exact claim. A missing or changed externally pinned policy stops
the hook/launcher path. A valid package provenance or report signature never
upgrades incomplete mediation into sandbox enforcement.

The enterprise deployment boundary is shown in
`docs/enterprise-deployment.md`; the threat and incident-derived requirements
are in `docs/concept.md` and `docs/research/incidents.md`.
