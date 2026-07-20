# Security incidents and derived requirements

This is a living threat-research log, not an exhaustive incident database.
Entries are included only when they change the specification, reference
implementation, or conformance tests.

## S1ngularity / malicious Nx packages (2025)

Compromised Nx packages ran a post-install script that searched developer
machines for sensitive data, invoked locally installed AI CLIs, and uploaded
results to public GitHub repositories using the GitHub CLI. This demonstrates
that model-facing tools, subprocesses, ambient credentials, and an otherwise
legitimate SaaS destination can form one exfiltration chain.

Derived requirements:

- Filesystem restrictions must be inherited by arbitrary subprocesses.
- Environment variables must be filtered before the agent and descendants run.
- Network policy cannot merely distinguish "known SaaS" from unknown domains;
  method, path, identity, and operation-specific authorization may matter.
- The agent should receive capabilities or short-lived scoped credentials, not
  ambient long-lived secrets.

Source: [Nx postmortem](https://nx.dev/blog/s1ngularity-postmortem).

## GitHub MCP secret exfiltration mitigations (2025)

GitHub added secret scanning and push protection to MCP tool-call payloads in
both read and write paths, explicitly describing prompt injection as a primary
secret-leak vector. This shows that scanning only final commits is too late;
every tool boundary and output channel needs mediation.

Derived requirements:

- String rules have named ingress and egress scopes.
- Tool inputs, tool outputs, network requests, logs, and file writes can require
  different effects.
- Encoders and transformations require adversarial tests; pattern scanning is a
  defense-in-depth layer, not a complete confidentiality boundary.

Source: [GitHub MCP secret-scanning announcement](https://github.blog/changelog/2025-08-13-github-mcp-server-secret-scanning-push-protection-and-more/).

## Amazon Q extension release compromise (2025)

AWS reported that an inappropriately scoped GitHub token in the Amazon Q
Developer extension's CodeBuild configuration let a threat actor commit
malicious code that was automatically included in version 1.84.0. AWS found
that the payload did not execute because of a syntax error, revoked the
credential, removed the affected release, and published version 1.85.0. This
is still a release-integrity failure: an enforcement adapter is part of the
trusted computing base, so its provenance matters as much as its policy.

Derived requirements:

- Build and release identities must be least-privileged, short-lived, and
  separated from ordinary repository automation.
- Adopters must pin and verify the reference implementation, adapter, compiled
  policy, and conformance evidence rather than auto-trusting a mutable latest
  release.
- Release workflows need artifact provenance, reproducible verification, and
  an emergency revocation path.
- A policy guarantee must name the exact adapter and harness versions; policy
  text alone cannot attest to a compromised enforcement binary.

Source: [AWS-2025-015 security bulletin](https://aws.amazon.com/security/security-bulletins/AWS-2025-015/).

## Comment and Control / agentic workflow hijacking (2026)

Researchers showed that attacker-controlled PR titles, issue bodies, comments,
and other workflow inputs could hijack production coding agents and exfiltrate
credentials. Their broader evaluation found thousands of potentially
hijackable GitHub workflows across multiple official agent actions. Some
exfiltration used GitHub itself, so a hostname allowlist alone would have
allowed the channel.

Derived requirements:

- Untrusted strings must retain provenance; content and instructions are not
  interchangeable.
- Review agents must run without repository/API secrets unless a narrowly
  scoped brokered capability is essential.
- Policy must cover GitHub-native sinks such as comments, commits, artifacts,
  logs, and issues—not only arbitrary HTTP hosts.
- A scanner must assume attackers will encode, split, or transform secrets.

Sources:

- [Comment and Control paper](https://arxiv.org/abs/2605.11229)
- [Cloud Security Alliance analysis](https://labs.cloudsecurityalliance.org/research/csa-research-note-comment-control-github-prompt-injection-20/)

## Cursor environment-variable allowlist bypass (2026)

A published Cursor advisory describes command allowlist bypass through
environment-variable expansion in non-default auto-run mode. The policy saw a
permitted command form while the shell executed attacker-influenced values.

Derived requirements:

- Decisions must be applied to the effective operation, not only the model's
  unexpanded command string.
- Environment values are a capability surface and require filtering.
- Shell allowlists are not a substitute for filesystem and network isolation.

Source: [GHSA-82wg-qcm4-fp2w](https://github.com/cursor/cursor/security/advisories/GHSA-82wg-qcm4-fp2w).

## Baseline threat taxonomy

NIST identifies indirect prompt injection as a way to hijack agents and leak
restricted resources. The `.aiignore` threat model assumes prompt injection
will sometimes succeed and relies on least privilege and complete mediation to
bound the consequence.

Source: [NIST AI 100-2e2025](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf).

## Test-bed implications

The conformance suite must include:

- direct and shell-mediated reads;
- symlinks and path traversal;
- ignored files reached through Git history, archives, compiler errors, and
  test output;
- variable-name case differences and shell expansion;
- URL redirects, userinfo, IDNs, alternate IP encodings, DNS-to-private targets,
  and allowed-host/forbidden-operation combinations;
- literal, glob, and RE2 patterns over each declared string scope;
- encoded, fragmented, and transformed secret fixtures;
- policy modification attempts and stale compiled-policy detection.
