# aiignore policy specification

Status: **Draft 0.1.0-alpha.1**
Normative version identifier: **`0.1`**

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** are to be interpreted as described by BCP 14
([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.html) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174.html)) when, and only when,
they appear in all capitals.

## 1. Scope

This specification defines:

1. a portable structured policy document named `.aiignore.yaml`;
2. deterministic decisions for file, environment, network, and string
   resources;
3. requirements for context-, tool-, and sandbox-level conformance;
4. language-neutral conformance inputs and outputs.

The document describes desired policy. A conforming harness is responsible for
enforcement. Merely parsing the file does not establish a security boundary.

## 2. File identity, compatibility, and serialization

The normative structured-policy filename is exactly `.aiignore.yaml`.
Implementations MAY accept an explicit alternate filename through an API or
command-line option, but automatic discovery MUST look for `.aiignore.yaml`.

The exact filename `.aiignore` is already used by deployed tools for
gitignore-style path exclusions. It is reserved as a compatibility input and
MUST NOT be interpreted as this structured policy format. An implementation
that imports `.aiignore` MUST apply the source tool's path syntax and MUST
report the import as context-only unless stronger mediation is independently
configured and tested. It MUST NOT silently promote an ignore pattern into a
tool- or sandbox-level security claim.

Implementations MUST also reject ASCII case variants such as `.AIIGNORE` as a
structured-policy path. This prevents the same directory entry from changing
meaning on case-insensitive volumes.

If both files exist, `.aiignore.yaml` is the only source of structured policy.
The files do not inherit from or override one another. A harness MAY also honor
`.aiignore` for legacy context filtering, but MUST identify that behavior
separately in its conformance report.

`.aiignore.yaml` MUST be UTF-8 encoded YAML 1.2 using only the JSON data model.
When conveyed with a media type, it SHOULD use the registered
`application/yaml` media type defined by
[RFC 9512](https://www.rfc-editor.org/rfc/rfc9512.html). Implementations MUST
NOT rely on the deprecated, unregistered `application/x-yaml`, `text/yaml`, or
`text/x-yaml` aliases for format detection.

Implementations MUST reject:

- byte-order marks other than an optional leading UTF-8 BOM;
- duplicate mapping keys;
- aliases, anchors, merge keys, and explicit or custom tags;
- multiple YAML documents;
- non-string mapping keys;
- values not admitted by the published JSON Schema;
- a document larger than the implementation's declared policy-size limit.

The reference limit is 1 MiB. Implementations MAY choose a lower limit but MUST
report it. Parsers MUST NOT construct application-specific objects from YAML
tags or execute code during parsing.

The root MUST contain `aiignore: "0.1"`. Unknown properties are rejected. A
future specification may reserve `extensions` for namespaced experimentation;
draft 0.1 does not.

## 3. Root object

```yaml
aiignore: "0.1"
metadata:                     # optional, non-normative
  name: example-policy
  description: Example

defaults:                     # optional
  files: allow                # allow | deny
  environment: allow          # allow | deny
  network: allow              # allow | deny
  strings: allow              # allow | deny

rules:                        # optional
  files: []
  environment: []
  network: []
  strings: []
```

Missing defaults are `allow`. Missing rule lists are empty.

Rule IDs MUST be unique across the entire document and match
`[a-z][a-z0-9._-]{0,63}`.

## 4. Common rule evaluation

Every rule has an `id`, an `effect`, an optional integer `priority` from
`-1000` through `1000`, and resource-specific match fields. Missing priority is
zero.

For a decision, an implementation MUST:

1. canonicalize the candidate as defined for the resource;
2. discard rules that do not include the candidate or operation/scope;
3. discard a rule if any of its `except` patterns match;
4. choose the matching rule with greatest priority;
5. when priorities tie, choose the rule appearing later in its resource list;
6. use the resource default when no rule remains.

String redaction has one additional composition step defined in section 8.

This is ordered-policy behavior, similar to the useful part of `.gitignore`,
but `except` means "this rule does not apply" rather than an implicit allow.
Authors SHOULD prefer a local `except` for a false-positive carve-out and an
explicit `allow` rule when intentionally overriding another rule.

The portable decision result MUST be the exact JSON object defined by
[`decision.schema.json`](../schema/decision.schema.json). Unknown fields are
forbidden in the portable serialization; an implementation MAY keep private
metadata internally but MUST remove it before interchange or conformance
comparison. The six fields `resource`, `effect`, `ruleId`, `matched`, `reason`,
and `policyDigest` are always present:

```json
{
  "resource": "file",
  "effect": "deny",
  "ruleId": "private-files",
  "matched": "**/.env*",
  "reason": "matched rule private-files",
  "policyDigest": "0000000000000000000000000000000000000000000000000000000000000000"
}
```

The all-zero digest above is illustrative only; an actual result contains the
SHA-256 of the exact policy bytes.

`policyDigest` is the lowercase SHA-256 of the exact policy bytes, including an
optional leading UTF-8 BOM. `reason` is human-readable, non-normative detail;
implementations MUST NOT use it for interoperability decisions and MUST NOT put
candidate secrets or configured string-pattern values in it.

`ruleId` and `matched` MUST both be `null` when the default applies, and MUST
both be strings when a rule applies. For file, environment, and network rules,
`matched` is the first matching inclusion pattern in that selected rule. For
string rules, `matched` MUST contain only the matcher type (`literal`, `glob`,
or `regex`) and MUST NOT echo the configured pattern or matched input.

`output` MUST be present only for an environment or string `redact` decision.
`appliedRuleIds` MUST be present only for a string `redact` decision and follows
the order defined in section 8. An evaluation error is not a decision object;
adapters MUST report it separately using a portable diagnostic code and MUST
fail closed in a security-enforcing mode. They MUST NOT fabricate a rule match
to represent a parsing or canonicalization failure.

An `audit` effect permits the covered operation or value to cross the boundary
unchanged and emits a secret-safe audit event; it is not a denial. At an
enforcement boundary, an implementation claiming audit support MUST emit the
event before permitting the operation. Failure of its required audit sink MUST
fail closed. Developer-only inspection commands MAY return the decision without
emitting an event when they are explicitly non-enforcing. If another decision
or evaluation error blocks the containing operation, the implementation MUST
NOT emit an audit event for a boundary crossing that did not occur.

## 5. File rules

```yaml
- id: private-files
  effect: deny                 # allow | deny | audit | read-only
  priority: 10
  operations: [discover, index, read, write, execute]
  paths: ["**/.env*", "secrets/**"]
  except: ["**/.env.example"]
```

`operations` defaults to all five operations. `read-only` evaluates as:

- `allow` for `discover`, `index`, and `read`;
- `deny` for `write` and `execute`.

Paths use gitignore-style glob concepts as implemented by the following
portable subset:

- `/` is the separator on every platform;
- `*` matches zero or more non-separator characters;
- `?` matches one non-separator character;
- `**/` at the start, `/**/` between segments, and `/**` at the end match
  zero or more complete path segments, following gitignore semantics;
- consecutive `*` characters elsewhere are ordinary segment-local `*`
  wildcards and do not cross `/`;
- character classes use `[abc]`, `[a-z]`, and `[!a-z]` syntax. Class contents
  MUST use printable ASCII without separators; malformed, empty, non-ASCII,
  and descending ranges are rejected. A leading `!` inside the class is the
  only class-negation syntax;
- every pattern is matched against the entire root-relative candidate path;
  there is no implicit basename search. A leading `/` is an optional explicit
  root marker and has no additional semantic effect. Authors MUST use `**/name`
  to match `name` at the root and at arbitrary descendant depths;
- a trailing `/` means the directory and all descendants;
- backslash is not an escape and MUST be canonicalized to `/` in candidates;
- brace expansion, extglobs, and negation inside a pattern are forbidden.

Candidate paths MUST be resolved relative to the declared policy root before
matching. Implementations MUST reject NUL, empty paths, and candidates that
escape the root. Sandbox-level implementations MUST resolve symlinks and other
platform aliases before granting access. A path that cannot be safely
canonicalized MUST be denied.

Matching is case-sensitive by default. A native case-insensitive filesystem
adapter, including the reference Windows mode, MUST ASCII-fold candidate and
pattern letters before matching, MUST NOT case-fold non-ASCII characters, and
MUST report that behavior in its conformance result.

`discover` covers names, metadata, and directory listings. Preventing file
contents while revealing a filename is `read` denial, not `discover` denial.

File rules apply to the canonical path being accessed; they do not attach
provenance labels to copied bytes. A pre-existing archive, cache, build output,
VCS object, diagnostic, or other allowed file MAY contain material originally
copied from a denied path. Implementations claiming sandbox-level file
confidentiality MUST test relevant alternate representations and report any
readable copies. Deployments that require content provenance MUST additionally
use sanitized checkouts, deny derived stores, or mediate content boundaries
with string/content policy.

## 6. Environment rules

```yaml
- id: credentials
  effect: drop                 # allow | drop | redact | deny | audit
  names: ["*_TOKEN", "*_SECRET", "AWS_*"]
  except: ["PUBLIC_*", "*_TOKEN_TTL"]
  replacement: "[REDACTED]"   # only valid for redact
```

Environment patterns use the file glob subset without `/` or `**`.
Candidate environment names MUST be non-empty and MUST NOT contain NUL or `=`.
Environment names are case-sensitive by default. A native Windows adapter MUST
match ASCII names case-insensitively because the platform environment is
case-insensitive, and MUST report that behavior in its conformance result.

Effects mean:

- `allow`: retain the name and value;
- `drop`: omit it from the agent and descendant environments;
- `redact`: retain the name with `replacement`, default `[REDACTED]`;
- `deny`: refuse to start the covered operation while it is present;
- `audit`: retain it and emit a non-secret audit event.

Audit output MUST NOT contain the original value. Environment values are also
subject to string rules at the `environment_value` scope after name rules. A
`drop` or `deny` name decision ends evaluation for that entry. Otherwise the
name rule first determines the retained or replacement value, then the string
rule evaluates that resulting value. A string `deny` omits the entry and adds
its name to the denied set; a string `redact` supplies the final value.

## 7. Network rules

```yaml
- id: approved-docs
  effect: allow                # allow | deny | audit
  urls:
    - "https://docs.example.com/**"
    - "https://registry.npmjs.org/**"
```

Network patterns MUST have the form `scheme://authority/path-pattern`.
Supported schemes in draft 0.1 are `http`, `https`, `ws`, and `wss`. The
authority may contain an exact DNS host, `*.` (subdomains only), `**.` (apex and
subdomains), an exact IPv4/IPv6 literal, and an optional exact port. Userinfo,
fragments, query markers, whitespace, control characters, backslashes,
wildcard ports, and wildcard IP literals are forbidden in the authority. A
`?` is valid only after the first `/`, where it is a path-glob token. Parsers
MUST reject lexical authority text that a URL library would silently discard
or reinterpret during normalization.

DNS names MAY contain Unicode that IDNA maps to valid A-labels. Empty labels,
labels longer than 63 ASCII bytes, names longer than 253 ASCII bytes, leading
or trailing label hyphens, underscores, percent escapes, and numeric spellings
that a URL parser would reinterpret as an IPv4 address are forbidden. One
trailing root dot MAY be discarded during canonicalization. IPv4 candidates
MUST use dotted-decimal spelling and IPv6 literals MUST use brackets.

An explicit port MUST contain decimal digits whose numeric value is between 0
and 65535 inclusive. Leading zeroes are removed before matching, and the
scheme's default port is represented as no explicit port.

The path uses the file glob subset, including `?` as a one-character path
wildcard. A `?` in a policy network pattern is always glob syntax, never the
start of a query component. Candidate URL queries are ignored for URL-pattern
matching. Query matching is intentionally excluded from draft 0.1; string
rules at `network_request` MUST be used for sensitive query or body data.

Before matching, implementations MUST:

1. parse the URL with a standards-conforming URL parser;
2. reject userinfo and fragments;
3. lowercase and IDNA-normalize the host;
4. remove the default port for the scheme;
5. normalize dot segments without decoding reserved separators;
6. uppercase hexadecimal digits in percent escapes;
7. reject malformed escapes and percent-encoded NUL, `/`, or `\\` bytes;
8. match the canonical scheme, host, port, and path.

Candidate URLs MUST use the lexical form `scheme://authority` followed by an
optional path, query, or both, with exactly two slashes after the scheme and a
non-empty authority. An omitted path canonicalizes to `/`. They MUST NOT
contain leading or trailing whitespace, ASCII control characters, or
backslashes. Network pattern paths MUST be printable ASCII; authors use UTF-8
percent encoding for non-ASCII path bytes. These restrictions avoid divergent
origin, proxy, and language-runtime interpretations of the same request target.

Every redirect is a new request and MUST be re-evaluated. Sandbox-level
implementations MUST prevent direct network paths that bypass the policy proxy.
They MUST define handling of DNS rebinding and loopback, link-local, private,
Unix-socket, and other non-public destinations. The recommended default is to
deny them unless an exact rule and administrative policy allow them.

An allowed host does not authorize every semantic action on that host. Harnesses
with structured tools SHOULD additionally mediate tool name, method, repository,
tenant, and side-effect annotations.

### 7.1 Resource decision budgets

File paths, environment names, and network URLs MUST be bounded before parsing
or matching. Draft 0.1 uses an exact 1 MiB UTF-8 candidate-byte ceiling,
reported as `candidate_too_large`.

Implementations MUST also bound cumulative matcher work across every applicable
rule and exception for these resources. Draft 0.1 charges the
canonical candidate's UTF-8 byte length before each file-pattern application
and the input candidate's UTF-8 byte length before each environment or network
pattern application. It fails closed before cumulative charged work exceeds
1 MiB, reported as `resource_work_limit`. These exact limits are normative for
draft 0.1 conformance so independent implementations produce the same portable
limit-vector results. This is a deterministic portability
budget, not a wall-clock timeout.

## 8. String rules

```yaml
- id: private-key
  effect: redact               # allow | deny | redact | audit
  scopes: [tool_output, network_request, log]
  patterns:
    - type: literal
      value: "sensitive marker"
      caseSensitive: true
    - type: regex
      value: "-----BEGIN [A-Z ]*PRIVATE KEY-----"
      caseSensitive: true
  except:
    - type: literal
      value: "fixture-only-value"
  replacement: "[REDACTED:private-key]"
```

Supported scopes are:

- `user_prompt`
- `model_input`
- `model_output`
- `tool_input`
- `tool_output`
- `file_read`
- `file_write`
- `environment_value`
- `network_request`
- `network_response`
- `log`

Missing `scopes` means all scopes.

Pattern types:

- `literal`: exact substring search;
- `glob`: the environment glob subset applied as an unanchored text pattern;
- `regex`: RE2 syntax, unanchored unless the pattern includes anchors.

Replacement strings are literal text for every pattern type. `$1`, `$&`,
backslashes, and other regular-expression replacement metacharacters MUST NOT
interpolate captures or reproduce matched input. Validation and decision errors
MUST NOT echo configured string-pattern values, which may themselves be secret.

`caseSensitive` defaults to `true`. When false, matching uses locale-independent
Unicode simple case folding compatible with RE2; locale-specific expansions
are forbidden. Regex patterns MUST be executed by a linear-time engine
compatible with RE2. Backreferences and look-around are not portable and MUST
be rejected.

Glob and regex patterns that match the empty string MUST be rejected. Empty
matches make replacement counts and cursor advancement differ across engines
and can create disproportionate output.

For `redact`, every non-overlapping occurrence MUST be replaced. The default
replacement is `[REDACTED:<rule-id>]`. An exception pattern exempts the entire
rule for a candidate string; it does not remove a substring from consideration.

Implementations MUST enforce maximum transformed-output bytes and replacement
count before those limits can cause disproportionate memory use. The normative
draft 0.1 limits are 16 MiB and 100,000 replacements per
pattern application, reported as `string_output_too_large` and
`string_replacement_limit`.

Implementations MUST also bound cumulative matcher work across all applicable
rules, exceptions, and redaction passes. Draft 0.1 charges the
UTF-8 byte length of the current candidate before every matcher application
and fails closed before cumulative charged work exceeds the normative 128 MiB,
reported as `string_work_limit`. This is a deterministic portability budget,
not a wall-clock timeout; it prevents a large value and many individually
linear patterns from composing into policy-driven denial of service.

All string-rule matching, including exceptions, MUST be evaluated against the
original candidate before any transformation. When the winning string rule has
`effect: redact`, every redact rule that matched that original candidate MUST
be applied, from greatest priority/latest rule to lowest priority/earliest
rule. Within each rule, patterns MUST be applied in their listed order to the
current transformed value. A transformation MUST NOT cause a previously
non-matching rule to join the redaction set. The decision MUST include
`appliedRuleIds` in rule-application order, including a selected rule whose
match was consumed by an earlier transformation. This makes overlapping
patterns deterministic across implementations. A winning `allow`, `deny`, or
`audit` rule remains an explicit whole-candidate override and suppresses
lower-precedence redactions.

`deny` prevents the value from crossing the named boundary. `audit` emits the
rule ID and scope but MUST NOT emit the matched secret. Implementations SHOULD
record a one-way digest only when an administrator has explicitly accepted the
correlation risk.

The portable event MUST validate against
[`audit-event.schema.json`](../schema/audit-event.schema.json) and contains only
`event`, `formatVersion`, `resource`, `ruleId`, and `policyDigest`. The reference
CLI writes one such JSON Lines event to standard error before starting a
filtered child and while evaluating hook decisions. The event MUST NOT include
the candidate, matched pattern, transformed output, environment value, URL,
path, or string scope. A deployment that needs those attributes MUST correlate
them in a separately protected system without changing the portable event or
recording secret material. A harness that suppresses standard error MUST
configure an equivalent secret-safe sink before claiming audit support.

String filtering is defense in depth. It does not prove confidentiality because
an agent may encode, split, summarize, transform, or infer protected content.

## 9. Policy discovery and integrity

Draft 0.1 defines one explicit policy root and does not recursively discover
nested policies. A CLI MAY default to `<workspace>/.aiignore.yaml`, but APIs
and conformance runners MUST accept an explicit path other than the reserved
legacy filename `.aiignore`.

When repository policy is discovered automatically, its containing directory
is the policy root. When policy is distributed outside the workspace, the
caller MUST provide the workspace root separately; implementations MUST NOT
infer that an administrator policy protects paths relative to its storage
directory. The reference launcher pins the exact path, root, and digest in
`AIIGNORE_POLICY_PATH`, `AIIGNORE_POLICY_ROOT`, and
`AIIGNORE_POLICY_SHA256` for its child harness and hooks.
These three names are reserved control-plane variables. When an inherited
`AIIGNORE_POLICY_SHA256` is present, the launcher MUST treat it as the expected
digest and fail closed on a mismatch. It MUST discard inherited path and root
values, filter the inherited environment, and then inject all three verified
values. Environment rules therefore apply to inherited instances, but MUST NOT
drop, redact, or replace the verified control-plane values. A launcher that
cannot provide the verified values exactly MUST fail closed.

Implementations MUST NOT load remote includes. They SHOULD compute a SHA-256
digest of the exact policy bytes and surface it in decisions and conformance
reports. Once that digest is computed, the parsed policy data used for
decisions MUST be immutable. A caller MUST NOT be able to change policy
semantics while decisions continue reporting the digest of earlier bytes.

Repository policy is untrusted when an attacker controls the repository. An
administrator MAY compose a separately distributed policy, but composition and
signed policy bundles are deferred to a later draft. Until then, hard-enforced
administrator policy MUST be compiled outside this document and MUST NOT be
weakenable by repository policy.

## 10. Failure behavior

Security-enforcing modes MUST fail closed when:

- policy loading, parsing, validation, canonicalization, or compilation fails;
- an adapter cannot represent a deny rule at its claimed conformance level;
- a policy changes after enforcement is installed for the session;
- an enforcement component is unavailable or reports an unknown version.

Developer-only validation and audit modes MAY fail open but MUST label the
result as non-enforcing.

### 10.1 Portable diagnostic codes

A failed operation is not an `allow` or `deny` decision. Implementations MUST
return an error separately and security-enforcing callers MUST treat it as
fail-closed. Portable parser and decision conformance uses these stable codes:

| Code | Meaning |
| --- | --- |
| `invalid_encoding` | Policy bytes are not permitted UTF-8. |
| `policy_too_large` | Policy exceeds the declared byte limit. |
| `invalid_yaml` | YAML is malformed, duplicated, or contains multiple documents. |
| `unsafe_yaml` | Forbidden aliases, anchors, tags, merge keys, or key types occur. |
| `schema_validation` | The data model does not satisfy the published schema. |
| `duplicate_rule_id` | A rule ID repeats anywhere in the document. |
| `invalid_pattern` | A file or environment glob is outside the portable subset. |
| `invalid_network_pattern` | A network pattern is malformed or ambiguous. |
| `invalid_string_pattern` | A string matcher is empty, unsafe, or outside RE2. |
| `invalid_path` | A file candidate is empty or contains NUL. |
| `path_escape` | A file candidate escapes the policy root. |
| `invalid_file_operation` | A file operation is outside the portable operation set. |
| `invalid_environment_name` | An environment name is empty or contains NUL or `=`. |
| `invalid_url` | A URL candidate is unsupported, malformed, or ambiguous. |
| `invalid_string_scope` | A string scope is outside the portable scope set. |
| `candidate_too_large` | A file, environment, or network candidate exceeds the declared byte limit. |
| `resource_work_limit` | Cumulative file, environment, or network matcher work exceeds the declared budget. |
| `string_output_too_large` | Redaction would exceed the transformed-output byte limit. |
| `string_replacement_limit` | Redaction would exceed the replacement-count limit. |
| `string_work_limit` | Cumulative string matcher work would exceed the declared deterministic budget. |

The reference file loader additionally emits `policy_not_found`,
`policy_unreadable`, `not_a_file`, `legacy_ignore_filename`,
`legacy_ignore_detected`, `policy_digest_mismatch`, and
`policy_changed_during_load`. The reference hooks additionally emit
`hook_input_limit` after 64 traversal levels, 4,096 traversed nodes, 128 named
candidates or environment references, or 1 MiB of aggregate named-candidate
bytes. Implementations MAY add diagnostic detail, but
MUST NOT include candidate secrets or configured string patterns in messages.

## 11. Conformance

Draft 0.1 defines two non-interchangeable conformance targets:

1. **implementation conformance** covers restricted-YAML parsing and portable
   decision semantics;
2. **harness conformance** covers live context, tool, or sandbox mediation by a
   named harness and enforcement backend.

An unqualified statement such as “aiignore conformant” is invalid. A claim MUST
name its target, exact specification and artifact bundle, implementation or
harness version, and scope. Passing implementation vectors does not establish
harness enforcement.

### 11.1 Implementation conformance

An implementation-conformance run MUST begin with the exact bytes of the
canonical conformance manifest. It MUST validate the manifest, verify every
executed parser- and decision-vector SHA-256 against it, and execute exactly one
parser vector pack plus every decision vector pack listed by that manifest. A
report MUST validate against
`schema/implementation-conformance-report.schema.json`.

Each suite entry MUST retain its kind, revision, canonical HTTPS URI, exact-byte
SHA-256, total, passed count, failed case IDs, and conformance result. Decision
suites MUST also retain the exact policy SHA-256. Suite URIs MUST be unique. The
summary counts MUST equal the sums of the suite counts; a suite is conformant
if and only if every case passed, and the report summary is conformant if and
only if every suite is conformant. Failure details MAY be stored separately,
but failed case IDs MUST NOT be omitted.

A consumer presenting the report as complete MUST independently validate the
exact manifest, verify the report's manifest digest and bundle identity, require
one report suite for every manifest-selected parser or decision artifact, and
verify each suite's URI, kind, revision, vector digest, and decision-policy
digest against the supplied artifact bytes. The consumer MUST also validate
each vector document, require the reported total to equal its case count, and
reject failed case IDs absent from that document. Report-schema validation or a
valid signature alone does not establish complete manifest membership or case
accounting.

The implementation classification has these meanings:

- `reference`: the implementation maintained with this specification;
- `derived`: parsing or decision logic copied, translated, generated from, or
  dependent on the reference implementation;
- `independent`: parsing and decision logic written from the normative
  specification without using reference decision code or expected vector
  results as implementation logic.

Classification is an assertion, not a cryptographic fact. An `independent`
claim requires public or otherwise reviewable source, dependency disclosure,
and provenance review. Reusing the schemas and vector inputs is expected and
does not by itself make an implementation derived.

An implementation report MUST state that it does not establish harness, tool,
or sandbox enforcement. It MUST NOT include candidates, configured string
patterns, policy source paths, or failure output that may contain secret
material.

### 11.2 Harness conformance

A harness-conformance statement and the report defined by
`schema/conformance-report.schema.json` MUST include:

- specification version and policy SHA-256;
- canonical HTTPS URI, revision, and SHA-256 of the exact harness-test-plan
  bytes that were executed;
- implementation and harness versions;
- full source commit, dirty-tree state, and test-runner SHA-256;
- operating system, architecture, and enforcement backend;
- each resource/operation and its achieved level (`context`, `tool`, or
  `sandbox`);
- unsupported, failed, untested, or partially mediated paths;
- result evidence and detached verification identity when status is `verified`.

Harness claims are invalid if known bypasses are omitted or successful cases
are reported without the required failed and untested scope. A result from one
operating system, architecture, harness version, model setting, or backend MUST
NOT be generalized to another.

### 11.3 Evidence status

Both report types use the following lifecycle:

- `provisional` is self-reported evidence and may come from a dirty development
  tree if that state is disclosed;
- `verified` requires a clean source state, the verification object, at least
  one content-addressed evidence artifact, and a valid detached signature;
- `withdrawn` requires a reason and MUST NOT be presented as current evidence.

“Verified” authenticates exact report bytes to a reviewed identity and key. It
does not prove independence, correctness of the test environment, completeness
of mediation, vendor endorsement, or certification.

### 11.4 Detached conformance signatures

The portable draft 0.1 signature format is an Ed25519 signature envelope that
validates against `schema/conformance-signature-envelope.schema.json`. The
payload is the exact UTF-8 bytes of an implementation- or harness-conformance
report whose status is `verified`. That report's `verification` object MUST use method
`aiignore-ed25519-v0.1` and include the signer identity, HTTPS envelope URI,
and SHA-256 of the signer's SubjectPublicKeyInfo DER bytes. An issuer is
optional; when present it MUST match in the report, envelope, and verifier's
trusted input.

The envelope `payloadType` selects both the report schema and domain separator:

| Payload type | Domain-separation ASCII bytes |
| --- | --- |
| `application/vnd.aiignore.conformance-report+json;version=0.1` | `AIIGNORE-CONFORMANCE-REPORT-SIGNATURE-V0.1` |
| `application/vnd.aiignore.implementation-conformance-report+json;version=0.1` | `AIIGNORE-IMPLEMENTATION-CONFORMANCE-REPORT-SIGNATURE-V0.1` |

The signed message is exactly the selected domain-separation ASCII bytes, one
NUL byte, and the 32 raw bytes represented by the lowercase SHA-256 of the
report. The envelope repeats the report SHA-256, identity, optional issuer,
public-key fingerprint, canonical SPKI PEM public key, and a canonical base64
Ed25519 signature.

A verifier MUST:

1. receive the expected identity and public-key SHA-256 through a trusted
   channel separate from the report and envelope;
2. validate the envelope, select the report schema from its exact payload type,
   validate the report, and require report status `verified`;
3. hash the exact report bytes and compare the envelope payload digest;
4. derive the SPKI DER fingerprint from the embedded Ed25519 public key and
   compare it with the envelope, report, and trusted fingerprint;
5. compare identity and issuer values with the report, envelope, and trusted
   inputs; and
6. verify the Ed25519 signature over the domain-separated message above.

An embedded key or self-asserted identity MUST NOT become a trust anchor merely
because its signature is mathematically valid. Signature verification proves
that the holder of the pinned key signed those exact report bytes; it does not
prove that the tests were complete, the signer was independent, or the
reported enforcement claim is correct.

### 11.5 Requirements traceability

The versioned, non-normative catalog at
`conformance/requirements-v0.1.json` maps every top-level section to reviewed
evidence, assurance classification, and residual limitations. Its schema is
`schema/requirements-traceability.schema.json`. The catalog improves audit
navigability; it does not add language semantics, define conformance, or turn
self-authored evidence into independent assurance.

## 12. Security considerations

The primary risks are incomplete mediation, confused-deputy behavior, prompt
injection, policy tampering, path aliasing, environment inheritance, unsafe URL
canonicalization, DNS rebinding, trusted-destination exfiltration, string-rule
evasion, and audit-log leakage.

Path isolation does not imply content provenance. Copies in archives, version
control, caches, logs, compiler diagnostics, or remote services are distinct
resources unless another policy rule covers their access or boundary.

The strongest architecture removes secrets from the agent runtime, gives the
agent scoped brokered capabilities, uses OS-level filesystem isolation and an
egress proxy, and treats content scanners as a final defense-in-depth layer.

## 13. Privacy and data minimization

A policy may reveal the names or locations of credentials, internal services,
repositories, tenants, and regulated data. Policy files, detailed adapter-gap
reports, and administrator overlays SHOULD be access-controlled as sensitive
configuration even when candidate values are absent.

Portable audit events intentionally omit candidates, paths, URLs, scopes,
matched patterns, and transformed values. Deployments MUST NOT add those fields
to the portable event. Richer telemetry belongs in a separately protected
system with explicit retention, access, purpose, and deletion controls.

Decision `matched` values for file, environment, and network resources reveal
configured policy patterns and therefore MUST NOT be copied into ordinary logs
without review. String decisions expose only matcher type. Errors MUST NOT echo
candidate values or configured string patterns. Conformance evidence MUST use
synthetic data and MUST NOT publish credentials, customer content, private
transcripts, personal paths, or internal hostnames.

Policy and report digests are stable correlation identifiers. Operators SHOULD
consider whether publishing or retaining them links otherwise separate
repositories, customers, or sessions. Redaction reduces accidental disclosure;
it is not anonymization and does not make retained content safe for unrelated
secondary use.

## 14. Internationalization and text processing

Policy documents are UTF-8. Metadata and string matcher values may contain
Unicode, while rule IDs, diagnostic codes, URL-pattern paths, and the portable
glob character-class subset are intentionally constrained as specified above.

The portable decision engine MUST NOT apply Unicode normalization to file
patterns, file candidates, environment patterns, or environment names. A
filesystem adapter MUST resolve the native filesystem's normalization and alias
behavior before granting access and MUST disclose platform behavior in harness
evidence. ASCII-only folding for native case-insensitive file and environment
matching remains distinct from Unicode simple case folding for explicitly
case-insensitive string matchers.

DNS host processing MUST produce the same ASCII host used by the WHATWG URL
host parser and MUST satisfy section 7's additional lexical restrictions.
Network paths compare their normalized ASCII percent-encoded representation;
implementations MUST NOT decode reserved separators before matching.

## 15. Versioning and canonical artifacts

The `aiignore` root field identifies policy-language compatibility as
`major.minor`. An implementation MUST reject an unsupported value; it MUST NOT
guess or silently downgrade. Patch and prerelease identifiers version the
specification text, schemas, vectors, and reference package without changing
the accepted root value when policy semantics remain compatible.

Canonical draft 0.1 artifacts are published at:

- `https://ap-in-indy.github.io/aiignore/spec/0.1/aiignore.md`
- `https://ap-in-indy.github.io/aiignore/spec/0.1/registries.md`
- `https://ap-in-indy.github.io/aiignore/spec/0.1/errata.md`
- `https://ap-in-indy.github.io/aiignore/schema/0.1/aiignore.schema.json`
- `https://ap-in-indy.github.io/aiignore/schema/0.1/decision.schema.json`
- `https://ap-in-indy.github.io/aiignore/schema/0.1/audit-event.schema.json`
- `https://ap-in-indy.github.io/aiignore/schema/0.1/readiness-report.schema.json`
- `https://ap-in-indy.github.io/aiignore/schema/0.1/implementation-conformance-report.schema.json`
- `https://ap-in-indy.github.io/aiignore/schema/0.1/conformance-report.schema.json`
- `https://ap-in-indy.github.io/aiignore/schema/0.1/conformance-signature-envelope.schema.json`
- `https://ap-in-indy.github.io/aiignore/schema/0.1/conformance-vectors.schema.json`
- `https://ap-in-indy.github.io/aiignore/schema/0.1/parser-vectors.schema.json`
- `https://ap-in-indy.github.io/aiignore/schema/0.1/harness-vectors.schema.json`
- `https://ap-in-indy.github.io/aiignore/schema/0.1/conformance-manifest.schema.json`
- `https://ap-in-indy.github.io/aiignore/conformance/0.1/manifest.json`
- `https://ap-in-indy.github.io/aiignore/vectors/0.1/`

Published release tags and assets are immutable. Corrections that do not alter
normative behavior are recorded in the authoritative errata index; normative
changes require an RFC, new vector revision, and an updated prerelease or
specification version. The closed registry companion governs allocation and
unknown-value handling for protocol tokens used by this specification.

## 16. Normative references

- BCP 14: [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.html) and
  [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174.html), requirements language.
- [RFC 9512](https://www.rfc-editor.org/rfc/rfc9512.html), YAML media type.
- [YAML 1.2.2](https://yaml.org/spec/1.2.2/), restricted as further defined in
  section 2.
- [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12), schema
  vocabulary and validation behavior.
- [WHATWG URL Standard](https://url.spec.whatwg.org/), URL and host parsing,
  restricted and made testable by section 7 and the canonical vectors.
- [Unicode UTS #46](https://unicode.org/reports/tr46/), non-ASCII domain-name
  mapping as incorporated by WHATWG URL host processing.
- [RE2 syntax](https://github.com/google/re2/wiki/Syntax), portable regular
  expression syntax and rejection of backreferences and look-around.
