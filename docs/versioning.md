# Versioning and compatibility policy

aiignore has several independently versioned surfaces. A package version, a
policy-language version, and a conformance-vector revision do not make the same
promise. Consumers MUST pin the surface on which their assurance depends.

## Versioned surfaces

| Surface | Identifier | Compatibility meaning |
| --- | --- | --- |
| npm reference implementation | Semantic Version, currently `0.1.0-alpha.1` | CLI and TypeScript API behavior for that immutable package release |
| policy language | top-level `aiignore`, currently `"0.1"` | normative syntax, canonicalization, selection, effects, and diagnostics |
| schemas | versioned canonical `$id` under `/0.1/` | exact validation contract for policy, decisions, audit/readiness output, vectors, reports, and envelopes |
| vector packs | `revision`, canonical URI, and exact SHA-256 | expected decisions or parse outcomes for one immutable vector document |
| conformance bundle | manifest version, URI, and SHA-256 | exact specification, schema, vector, and harness-plan membership |
| implementation reports | report schema, source identity, bundle digest, and suite identities | parser/decision interoperability for one exact implementation source |
| harness reports | report schema, harness/backend versions, vector identity, policy digest | scoped observation for one exact execution environment |

The Git tag, `package.json` version, release-note filename, changelog entry, and
`CITATION.cff` version MUST agree for an official release. Released tags,
packages, manifests, schemas, vectors, and reports are immutable. Corrections
are published under new identifiers; they are never overwritten in place. The
canonical `spec/errata.md` index records verified errors without changing old
bytes, while `spec/registries.md` controls allocation and reservation of
protocol tokens.

## Pre-1.0 package policy

The npm package follows Semantic Versioning. While the package is below 1.0 and
marked as a prerelease, its public API is intentionally unstable. Even so, the
project applies these stricter rules:

- a patch-prerelease increment may fix an implementation, packaging, test, or
  documentation defect without changing normative policy outcomes;
- a package release that intentionally changes a valid policy's normative
  decision requires a new policy-language version and an accepted RFC;
- removing or renaming a public export, CLI command, JSON field, or exit status
  requires release-note migration guidance;
- security fixes may fail closed on inputs previously accepted only when the
  prior behavior violated an existing normative safety requirement. The
  affected input and rationale MUST be recorded in release notes and vectors;
- prerelease users receive no automatic compatibility window. Production
  evaluations MUST pin an exact package version and conformance-manifest digest.

No `latest` npm dist-tag may point to a prerelease. The current release workflow
accepts only `alpha.N` versions, publishes through the explicit `alpha` tag, and
rejects a nonempty `latest` value unless it is a stable Semantic Version. An
unpublished candidate must compare strictly newer than the current global
`alpha` target before publication; immutable reruns never move the tag.

## Policy-language evolution

A parser MUST reject an unsupported `aiignore` value; it may not guess, coerce,
or silently use the nearest supported version. Within one published language
version:

- normative syntax and decisions are frozen;
- editorial clarification may explain existing behavior but may not change a
  conforming outcome;
- newly discovered ambiguity is resolved through an RFC, new portable vectors,
  and, when implementations could reasonably disagree, a new language version;
- new optional fields are not assumed to be backward compatible merely because
  older parsers ignore YAML keys—the schema rejects unknown fields by design.
- registry values are closed within a language version; aliases, vendor
  prefixes, and private-use values are not conforming extension points.

An implementation supporting multiple language versions MUST select semantics
from the explicit document version and report that version. It must not combine
rules from different versions in one policy.

## Vector and schema changes

Any content change to a published vector pack requires a new `revision` and
SHA-256. Any change to validation semantics requires a new canonical schema
identifier. The conformance manifest must then be regenerated as a new
versioned bundle. Old reports continue to refer to the old bytes and are not
retroactively upgraded.

Adding a regression without changing the policy language is permitted when it
tests behavior already required unambiguously by the published specification.
Release notes must identify why the addition is non-normative.

## Support and end of life

Only the latest prerelease and current `main` receive fixes during the alpha.
Publishing a newer prerelease ends routine support for the previous prerelease;
the prior artifacts and advisories remain available for reproducibility. A
security issue affecting an older release is documented publicly after
coordinated disclosure, but the remediation may be “upgrade to the latest
prerelease.”

Before 1.0, the project will publish a separate stable-support policy with a
defined deprecation period. No current document promises long-term support.

## Consumer pinning checklist

Enterprise consumers should record:

1. npm package name, exact version, tarball SHA-512 integrity, and provenance;
2. Git tag and verified release-signing identity;
3. conformance-manifest URI and SHA-256;
4. policy-language version and exact policy digest;
5. harness, adapter, OS, architecture, sandbox, and egress-backend versions;
6. verified report identity, key fingerprint, status, and known gaps.

A floating branch, npm dist-tag, mutable Pages URL without a pinned checksum, or
unversioned harness name is insufficient evidence for a deployment decision.
