# Security policy

## Project status

This repository is an alpha specification and reference implementation. It has
not received an independent security audit. Do not use the reference CLI as the
sole control protecting production credentials.

Machine-readable project security metadata is published in
[`security-insights.yml`](security-insights.yml). The accompanying
[`docs/security-baseline.md`](docs/security-baseline.md) is a maintainer
self-assessment and explicitly identifies controls that are not yet active or
independently verified.

The `filter-env` CLI reports variable names and policy actions only. It does not
offer an option to print retained environment values; use the in-process
library result only inside a trusted launcher that immediately passes the
filtered map to a child process.

## Reporting vulnerabilities

Use [GitHub private vulnerability reporting](https://github.com/ap-in-indy/aiignore/security/advisories/new)
when it is available. Before repository publication, or if that channel is
unavailable, email `alex@alexdoes.it` with the subject `aiignore security`.

Do not open a public issue for an unpatched vulnerability. Never include live
credentials, customer data, or an unnecessary full repository archive. Use a
synthetic reproducer and state the affected version, impact, and prerequisites.

Acknowledgement and remediation are best-effort while the project is in alpha.
Receipt is normally acknowledged within five business days. The maintainer
will establish a private tracking record, validate scope without requesting
real customer data, assess affected versions and interfaces, and agree on a
coordinated disclosure date with the reporter.

There is no guaranteed remediation SLA. As triage targets, critical issues are
assessed within two business days after acknowledgement, high-severity issues
within five, and lower-severity issues within ten. Severity considers policy
bypass, secret exposure, arbitrary code execution, release compromise,
preconditions, default reachability, and the difference between reference
decision logic and actual harness enforcement. CVSS may supplement but does not
replace this threat-model-specific assessment.

Public disclosure normally includes affected versions, impact, prerequisites,
remediation or upgrade guidance, credit when desired, and links to regression
tests. Publication may be delayed for a credible downstream remediation need,
or accelerated for active exploitation or prior public disclosure. Security
advisories, release notes, and the changelog retain the public record; reports
and conformance evidence are withdrawn or superseded rather than silently
rewritten.

## Supported versions

Only the latest alpha release and the current `main` branch receive security
fixes. Earlier alpha releases may require upgrading because the specification
and APIs are intentionally unstable. Publishing a new prerelease ends routine
support for the previous prerelease. See `docs/versioning.md` for the complete
compatibility and end-of-life policy.

## Dependency and static-analysis findings

Any known production dependency vulnerability at or above the repository's
`low` audit threshold is a release blocker unless a reviewed record proves the
affected path is not exploitable and states a removal/update deadline. Unknown
or unapproved production licenses also block release. High/critical static
analysis findings and exploitable lower-severity findings block release;
suppression requires a documented technical rationale and compensating control.

When a component vulnerability does not affect the project, the rationale is
recorded in the advisory/dependency decision and will be emitted as VEX with a
release once a production finding requires it. See
`docs/dependency-management.md`.

## Claim language

Implementations must report conformance per resource and operation:

- `context`: indexing and model-context exclusion;
- `tool`: harness tool mediation;
- `sandbox`: enforcement below the model, including subprocess descendants.

An implementation must not call itself "aiignore secure" or "fully
compliant" without a versioned conformance report. Passing context tests does
not imply that shell commands, MCP tools, environment variables, or network
traffic are isolated.

## Policy integrity

Repository-local `.aiignore.yaml` is controlled by the repository and may be
attacker-modifiable. High-assurance installations should:

1. distribute policy or a policy digest through an administrator-controlled
   channel;
2. compile enforcement before processing untrusted repository content;
3. reject policy changes until a new trusted session begins;
4. fail closed if the policy cannot be parsed, validated, compiled, or applied;
5. protect the enforcement binary, adapter, and audit log from agent writes.
