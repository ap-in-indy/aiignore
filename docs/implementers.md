# Implementer guide

This guide is non-normative. It translates the draft specification into a
portable implementation sequence and identifies where adapters must stop and
report a gap rather than silently widening access.

## Processing pipeline

An implementation should keep parsing, policy decisions, boundary enforcement,
and conformance reporting as separate modules:

```text
exact policy bytes
  -> bounded UTF-8 decoder
  -> restricted YAML syntax inspection
  -> JSON Schema validation
  -> semantic pattern validation
  -> immutable policy + SHA-256
  -> canonical resource candidate
  -> deterministic decision
  -> harness boundary / sandbox enforcement
  -> versioned conformance evidence
```

Never allow a permissive adapter compilation to become the source policy. The
`.aiignore.yaml` bytes and digest remain authoritative; generated vendor files are
cache artifacts with explicit gaps.

## Restricted YAML

Reject unsafe syntax before converting YAML nodes into ordinary objects:

1. Bound the byte input before allocation; the reference limit is 1 MiB.
2. Decode fatal UTF-8, permitting only an optional leading UTF-8 BOM.
3. Parse one YAML 1.2 document with unique keys and the core/JSON-compatible
   scalar model.
4. Walk the syntax tree and reject aliases, anchors, explicit tags, merge keys,
   non-string mapping keys, and extra documents.
5. Convert to plain data and validate against `schema/aiignore.schema.json`.
6. Validate portable glob, URL-pattern, and RE2 constraints.
7. Compute SHA-256 over the exact original bytes, not reserialized YAML.
8. Deep-freeze or otherwise make the validated policy immutable before exposing
   it to decision or adapter code.

Error messages should identify a rule and field without echoing string-pattern
values, environment values, request bodies, or secret-bearing source excerpts.
Cap multi-error output.

## Decision algorithm

The same selection function applies to each resource after resource-specific
canonicalization:

```text
matches = []
for rule at index i:
  skip if operation/scope is not covered
  skip if any rule-local exception matches
  if any include pattern matches:
    matches += (rule, i, matched-pattern)

winner = maximum matches by (priority, list-index)
return resource default if no winner
return winner effect otherwise
```

Higher integer priority wins. At equal priority, the later rule wins. An
`except` discards only its containing rule; it is not an implicit allow.

Serialize portable decisions with no extension fields and validate them against
`schema/decision.schema.json`. Defaults have both `ruleId` and `matched` set to
`null`; rule decisions have both set to strings. Redaction fields are
resource-specific, not optional decorations: environment redaction requires
`output`, and string redaction requires both `output` and ordered
`appliedRuleIds`.

Keep evaluation failures separate from decisions. A malformed path or URL has a
portable diagnostic code and causes fail-closed enforcement, but it did not
match a deny rule. Do not invent a rule ID or overload a default decision to
represent that failure.

Treat `audit` as allow-with-observation, not as a fourth enforcement outcome.
Before a covered operation proceeds, emit the exact secret-safe object in
`schema/audit-event.schema.json`. Do not add the candidate, URL, path, scope,
matched pattern, replacement, or value. A required audit sink failure is an
enforcement failure. Emit only after the containing multi-resource operation is
otherwise permitted; a denied operation did not produce an audited crossing.

String redaction is the one composition rule: determine every match against the
original candidate; when `redact` wins, apply each originally matching redact
rule from highest precedence to lowest, and each rule's patterns in listed
order. Do not add a rule merely because an earlier replacement created a new
match. A winning `allow`, `deny`, or `audit` suppresses lower redactions.

## Canonicalization checklist

### Files

- Resolve relative candidates against one explicit policy root.
- Normalize separators to `/` for matching.
- Reject empty/NUL paths and lexical escapes.
- Match the complete root-relative string. A pattern without `/` is root-only;
  use `**/name` for root and descendant basename matching. A leading `/` is an
  explicit root marker with the same behavior as the otherwise identical
  pattern.
- At sandbox level, resolve symlinks, hard-link/volume aliases, and platform
  path equivalences before granting access.
- Treat VCS objects, archives, caches, diagnostics, and copied build outputs as
  separate resources; path rules do not label copied bytes.

### Environment

- Match names case-sensitively except on native Windows, where ASCII names are
  case-insensitive.
- Filter the environment before starting the harness so descendants inherit the
  filtered map.
- Record name-rule and `environment_value` string decisions separately so a
  value redaction or denial is not mislabeled as a name-rule allow.
- Never include the original value in decisions, errors, or audit records.
- Apply `environment_value` string rules after name rules.

### Network

- Use a WHATWG-compatible URL parser and accept only HTTP(S)/WS(S).
- Reject syntactic userinfo, including empty userinfo erased by URL parsers.
- Normalize IDNs, case, trailing DNS dots, default ports, IP spellings, and dot
  segments before matching.
- Re-evaluate every redirect.
- Enforce DNS/private-address and rebinding policy at the transport or egress
  proxy, not only against the model-provided URL string.

### Strings

- Use a linear-time RE2-compatible engine.
- Charge a deterministic cumulative byte-work budget before each matcher and
  replacement pass; linear-time matchers can still compose into excessive work.
- Treat patterns themselves as potentially sensitive configuration.
- Preserve boundary scope; scanning only final model output is insufficient.
- Expect encoding, splitting, transformation, and summarization to evade
  pattern rules. String mediation is defense in depth.

## Adapter rule

For each policy rule, an adapter must choose exactly one outcome:

1. enforce it at a named context/tool/sandbox level;
2. enforce a provably more restrictive result and report the semantic change;
3. reject compilation; or
4. emit an error-severity gap and refuse an exact-conformance claim.

Silently dropping, broadening, or changing ordered-rule semantics is never a
valid export. Repository hooks are also not administrator controls: a hostile
repository can modify them unless deployment pins the hook and policy outside
the workspace.

## Conformance integration

Consume every JSON file in `test/conformance/` that validates against
`schema/conformance-vectors.schema.json`. Preserve its canonical URI and hash
the exact bytes before execution. Compare `effect`, `ruleId`, and the optional
redacted `output`. Do not copy expected results from the reference engine into
another implementation; run the cases independently.

Decision vectors may encode large candidates with `candidateRepeat` instead of
committing repeated megabytes. Materialize only after validating the vector
container and enforce the declared generated-candidate byte cap before
allocation.

Start an interoperability run from
`conformance/manifest-v0.1.json`. Validate it against the manifest schema, pin
the manifest bytes through a reviewed package or release attestation, and then
verify every listed artifact SHA-256 before parsing or executing vectors. The
manifest deliberately binds the specification, all conformance schemas, every
portable vector pack, and the published harness plan as one versioned bundle.
HTTPS location alone does not authenticate a manifest; consumers still need a
trusted package, signed release, or independently pinned digest.

Do not apply platform newline conversion to downloaded or checked-out vector
files. The reference repository enforces LF bytes through `.gitattributes` so
the same published SHA-256 is observed on Windows, macOS, and Linux.

Implementation interoperability and live harness enforcement are separate
claim types. A parser/decision implementation report validates against
`schema/implementation-conformance-report.schema.json`; a live harness report
validates against `schema/conformance-report.schema.json`. Never use the latter
to imply that an engine is independently implemented, or the former to imply
that a harness mediates access.

The bundled runner can execute every parser and decision pack selected by the
manifest against the TypeScript reference implementation and emit one
content-addressed provisional report:

```sh
aiignore reference-conformance-report \
  --date 2026-07-16 \
  --source-uri https://example.invalid/aiignore-source.tar.gz \
  --source-revision REVIEWED_REVISION \
  --source-sha256 REVIEWED_SOURCE_ARCHIVE_SHA256 \
  --runner-sha256 REVIEWED_RUNNER_ARTIFACT_SHA256 \
  --manifest conformance/manifest-v0.1.json \
  > provisional-implementation-report.json
```

This command hardcodes implementation name `aiignore`, language
`TypeScript`, and classification `reference`; it has no option to attribute the
reference run to another implementation. An independent or derived
implementation MUST execute its own code and serialize the shared report
schema with its own runner. Its classification remains self-asserted until
reviewers examine source and provenance.

`--source-sha256` identifies the exact reviewable source artifact; it is not
interchangeable with a Git commit identifier. Use `--source-dirty` when the
tested reference implementation was not built from that exact clean source.
`--runner-sha256` identifies the complete reviewable runner artifact, such as
the exact npm package tarball; it is not a digest of only the CLI entry file.
Report output deliberately contains only failed case IDs, not candidate values
or detailed failure output.

Before accepting an implementation report as complete, verify its exact bundle
membership offline against the pinned manifest and artifact bytes:

```sh
aiignore verify-implementation-report provisional-implementation-report.json \
  --manifest conformance/manifest-v0.1.json
```

This rejects a report that binds a different manifest, omits a selected suite,
changes suite identity metadata, or is inconsistent with the vector bytes. It
does not authenticate the producer; for verified evidence, run this check and
then verify the detached signature with separately obtained trust pins.

Harness reports validate against `schema/conformance-report.schema.json` and
must retain failed and untested cases. A report proves behavior only for its
exact policy digest, vector revision, harness version, operating system, and
backend.

Verified reports use the detached Ed25519 envelope defined in specification
section 11.4 and `schema/conformance-signature-envelope.schema.json`. A verifier
must require the expected identity and SPKI DER SHA-256 from a trust channel
outside the report/envelope pair. The reference `sign-report` command promotes
a clean provisional report with content-addressed evidence; `verify-report`
checks exact bytes, schema, identity, optional issuer, key fingerprint, and
signature.

## Minimum adopter checklist

- Parser rejects all unsafe-YAML fixtures.
- Decision engine passes both baseline and security vector packs.
- Environment is filtered before harness startup.
- Direct tools, subprocesses, MCP/apps, browser tools, and redirects are mapped.
- Path, symlink, VCS-history, archive, DNS/private-address, and policy-tampering
  tests are run where applicable.
- Every known bypass appears as a failed, partial, or untested report entry.
- Administrative policy and binaries are protected from repository writes.
- Harnesses, adapters, compiled policies, and reports are version-pinned and
  integrity-verified; release identities do not reuse broad repository tokens.
