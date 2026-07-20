# aiignore draft 0.1 registries

Status: **Normative companion to draft 0.1**

This document records the closed protocol-token registries used by the
aiignore draft 0.1 specification. It prevents an implementation, adapter, or
vendor from silently assigning new semantics to an existing 0.1 document.
The specification and schemas define the behavior of each value; this registry
defines allocation and compatibility policy.

## Registry policy

All draft 0.1 registries are **closed**. An implementation MUST reject an
unknown normative value where the corresponding schema does not admit it. A
vendor-prefixed value, case variant, alias, or undocumented extension is still
unknown and MUST NOT be treated as a registered value.

Adding, removing, or changing the meaning of a registered value requires:

1. an accepted RFC with compatibility, security, privacy, and failure-mode
   analysis;
2. a new policy-language minor version when policy syntax or decisions change;
3. updated schemas, portable vectors, coverage contracts, and reference tests;
4. a new immutable conformance-bundle digest; and
5. migration guidance for implementations and stored policies.

Editorial clarification that does not change observable behavior follows the
errata process. It does not allocate a value. Values are lowercase ASCII and
case-sensitive unless the defining specification section says otherwise.
Removed values remain reserved and MUST NOT be reused with different meaning.

## Policy-language version

| Value | Status | Meaning |
| --- | --- | --- |
| `0.1` | Experimental | Draft 0.1 restricted-YAML policy and decision semantics. |

## Resources

| Value | Status | Meaning |
| --- | --- | --- |
| `file` | Registered | A root-relative filesystem candidate and operation. |
| `environment` | Registered | An environment-variable name or value boundary. |
| `network` | Registered | A canonical network URL candidate. |
| `string` | Registered | Text evaluated at a named ingress or egress scope. |

## File operations

| Value | Status |
| --- | --- |
| `discover` | Registered |
| `index` | Registered |
| `read` | Registered |
| `write` | Registered |
| `execute` | Registered |

## Rule effects

The valid effects depend on the resource. `read-only` is a file-rule input
that produces portable `allow` or `deny` decisions; it is not a portable
decision effect.

| Resource | Registered rule effects |
| --- | --- |
| defaults | `allow`, `deny` |
| file | `allow`, `deny`, `audit`, `read-only` |
| environment | `allow`, `drop`, `redact`, `deny`, `audit` |
| network | `allow`, `deny`, `audit` |
| string | `allow`, `deny`, `redact`, `audit` |
| portable decision | `allow`, `deny`, `drop`, `redact`, `audit` |

## String scopes

| Value | Status |
| --- | --- |
| `user_prompt` | Registered |
| `model_input` | Registered |
| `model_output` | Registered |
| `tool_input` | Registered |
| `tool_output` | Registered |
| `file_read` | Registered |
| `file_write` | Registered |
| `environment_value` | Registered |
| `network_request` | Registered |
| `network_response` | Registered |
| `log` | Registered |

## String pattern types

| Value | Status | Meaning |
| --- | --- | --- |
| `literal` | Registered | Exact literal search under the specified case behavior. |
| `glob` | Registered | Portable string glob syntax from specification section 8. |
| `regex` | Registered | The restricted RE2-compatible expression subset. |

## Assurance levels

| Value | Status | Meaning |
| --- | --- | --- |
| `context` | Registered | Context selection or indexing behavior only. |
| `tool` | Registered | Named harness-tool mediation. |
| `sandbox` | Registered | Enforcement below the model across applicable descendants. |

These levels are per resource and operation. They are not ordered badges and
MUST NOT be collapsed into an unqualified conformance or security claim.

## Report and signature identifiers

| Registry | Registered value |
| --- | --- |
| implementation report media type | `application/vnd.aiignore.implementation-conformance-report+json;version=0.1` |
| harness report media type | `application/vnd.aiignore.conformance-report+json;version=0.1` |
| signature method | `aiignore-ed25519-v0.1` |
| signature algorithm | `ed25519` |
| report lifecycle | `provisional`, `verified`, `withdrawn` |
| implementation classification | `reference`, `derived`, `independent` |

## Portable diagnostic codes

| Value | Status |
| --- | --- |
| `invalid_encoding` | Registered |
| `policy_too_large` | Registered |
| `invalid_yaml` | Registered |
| `unsafe_yaml` | Registered |
| `schema_validation` | Registered |
| `duplicate_rule_id` | Registered |
| `invalid_pattern` | Registered |
| `invalid_network_pattern` | Registered |
| `invalid_string_pattern` | Registered |
| `invalid_path` | Registered |
| `path_escape` | Registered |
| `invalid_file_operation` | Registered |
| `invalid_environment_name` | Registered |
| `invalid_url` | Registered |
| `invalid_string_scope` | Registered |
| `candidate_too_large` | Registered |
| `resource_work_limit` | Registered |
| `string_output_too_large` | Registered |
| `string_replacement_limit` | Registered |
| `string_work_limit` | Registered |

These codes are normative as defined by specification section 10 and the
portable vectors. New code allocation follows the same RFC and bundle
versioning requirements; an implementation MUST NOT reinterpret an existing
code for a different failure class. Reference-only loader, hook, CLI, and
artifact-verifier errors are not portable registry allocations.

## Private-use and experimental extensions

Draft 0.1 defines no private-use token range and no in-document extension
point. Experimental behavior belongs in a separately named adapter or wrapper
format and MUST NOT be serialized as a conforming `.aiignore.yaml` 0.1 policy,
portable decision, or conformance report. This keeps unknown-value rejection
interoperable and prevents vendor experiments from becoming accidental
standards allocations.
