# Conformance evidence and claim policy

This policy defines what the project will accept as conformance evidence. It is
not a certification program, trademark license, vendor endorsement, or promise
that a harness is secure.

## Evidence classes

| Class | Meaning |
| --- | --- |
| Reference | The TypeScript implementation produced the result against its own tests or vectors. Useful as an oracle, but not independent evidence. |
| Independent | Public source not derived from the reference decision code produced the result from the normative specification and published bytes. |
| Harness | A named harness, OS, architecture, adapter, and enforcement backend executed a versioned live plan. |
| Verified | The report's exact bytes have a valid detached signature from an identity and public-key fingerprint supplied through an independent trust channel. |

“Verified” authenticates evidence; it does not promote a reference result to an
independent result and does not prove complete mediation.

## Claim targets

| Target | Portable schema | What a passing report establishes |
| --- | --- | --- |
| Implementation | `implementation-conformance-report.schema.json` | Restricted-YAML and decision compatibility for every parser/decision pack in one exact manifest. |
| Harness | `conformance-report.schema.json` | Scoped observation of named context/tool/sandbox cases on one exact harness, platform, and backend. |

“aiignore conformant” without one of these targets and its exact scope is not an
accepted claim. An implementation report cannot establish enforcement, and a
harness report cannot establish that its parser or engine was independently
implemented.

## Required harness-report scope

Every accepted report must identify:

- the report-schema and policy-language versions;
- implementation or harness name and exact version;
- source commit or immutable artifact digest;
- operating system, architecture, adapter, sandbox, and network backend when
  applicable;
- canonical vector URI, revision, and SHA-256;
- exact policy digest and runner digest;
- every required case as passed, failed, or untested;
- enforcement level separately for each resource and operation;
- known unmediated paths, semantic changes, and environmental prerequisites.

Selective success-only results are invalid. Unsupported and untested cases may
not be omitted or converted to passes. A result from one operating system,
harness build, or backend does not generalize to another.

An implementation report must bind the complete manifest, include exactly one
parser pack and every listed decision pack, preserve every failed case ID, and
pass the schema plus arithmetic/uniqueness invariants in specification section
11.1. Its `reference`, `derived`, or `independent` classification remains an
assertion until source provenance is reviewed.

Reviewers must run `verify-implementation-report` (or an equivalent independent
verifier) against the separately pinned manifest and artifacts. JSON Schema and
signature checks do not prove that the report contains every manifest-selected
suite.

## Independent implementation requirements

An implementation counts as independent only when its parser and decision
logic were written from the specification rather than copied, translated, or
generated from the reference implementation. Reusing JSON Schemas and portable
vector bytes is expected. Reusing expected results as implementation logic is
not independent.

The submission must provide public source or a reproducible public artifact,
license terms permitting review, build/run instructions, and disclosure of any
shared libraries that implement normative parsing or matching behavior.

## Harness evidence requirements

Harness reports must execute the published plan without weakening setup or
assertions. They must map direct tools, shell and subprocess descendants,
MCP/apps, browser paths, Git and archives, diagnostics, logs, redirects, DNS,
and background services as applicable. Missing paths remain explicit failures
or untested gaps.

Model-driven evidence is supplemental to deterministic no-model probes. A
model declining to attempt a bypass is not proof that the boundary would have
blocked it.

## Submission and review

Submit public evidence through the conformance issue form. Maintainers verify:

1. schema validity, exact-byte artifact identities, and complete manifest membership;
2. complete case accounting and claim scope;
3. source/build provenance and independence classification;
4. signature trust pins when a verified status is requested;
5. reproducibility on a clean environment where practical;
6. absence of credentials, customer data, and secret-bearing transcripts.

Acceptance records evidence in the repository but does not imply endorsement.
The submitter remains responsible for rights to the evidence and accuracy of
the environment description.

## Status and withdrawal

Reports use these lifecycle states:

- `provisional`: structurally valid evidence awaiting independent confirmation;
- `verified`: exact bytes authenticate to a reviewed signer identity and key;
- `withdrawn`: known to be invalid, misleading, compromised, or superseded for
  security reasons; the historical record and withdrawal reason are retained.

Reports are never silently edited. A correction receives a new content digest
and, when applicable, a new signature envelope. Discovery of an omitted path,
invalid runner, compromised key, or non-reproducible result triggers withdrawal
or a clearly linked superseding report.

## Permitted claim language

Acceptable:

> Harness X version Y passed file-read sandbox cases 1–8 from vector revision Z
> on operating system A using backend B; archive and browser paths were untested.

Not acceptable:

- “aiignore certified,” “fully compliant,” or “secure” without scope;
- a single badge collapsing context, tool, and sandbox levels;
- treating a valid signature, package attestation, or vector pass as proof that
  all runtime paths are mediated;
- vendor or project endorsement without a separate written agreement.

No conformance mark exists during the alpha. Future certification or trademark
language requires the governance and IPR work described in
`docs/intellectual-property.md`.
