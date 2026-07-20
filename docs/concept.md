# Concept and project tracker

## Mission

Create a portable aiignore policy standard and reference implementation that lets
people express what an AI agent must not discover, read, modify, inherit,
transmit, or reproduce. Make enforcement claims testable rather than relying on
the model to follow a prose instruction.

## Non-goals

- Claiming that a repository file alone can constrain a hostile process.
- Replacing secret managers, short-lived credentials, least privilege, or
  ordinary data-loss-prevention controls.
- Treating prompt compliance as access control.
- Loading remote policy includes. Policy must be available before network or
  untrusted repository content is processed.

## Threat model

The protected party trusts the harness and its enforcement layer, but does not
trust:

- model output or reasoning;
- repository content, including instructions in source, issues, PRs, build
  logs, generated files, or dependencies;
- subprocesses launched at the model's request;
- symlinks, alternate path spellings, archives, Git history, caches, or tool
  output as ways to bypass a direct file check;
- external URLs, redirects, DNS responses, MCP servers, or approved SaaS APIs;
- string encodings intended to evade secret scanners.

The repository owner may control `.aiignore.yaml`. For higher-assurance deployments,
an administrator must distribute a policy or compiled sandbox profile outside
the repository and prevent local weakening.

## Required resources

- **Files:** glob patterns, operations, symlink-safe canonicalization, explicit
  exceptions, read-only carve-outs.
- **Environment:** variable-name patterns, drop/redact/deny decisions, explicit
  exceptions, Windows case-folding guidance.
- **Network:** canonical URL patterns, deny/allow policy, redirects, DNS and
  private-address handling, network-capable non-shell tools.
- **Strings:** literal, glob, and linear-time regular expressions across named
  ingress/egress scopes with deny, redact, and audit effects.

## Assurance model

| Level | Name | Required behavior |
| --- | --- | --- |
| L1 | Context | Indexers, retrieval, attachments, and automatic context exclude matches. |
| L2 | Tool | Every declared harness tool is mediated, including MCP/app tools. |
| L3 | Sandbox | OS/network enforcement covers built-ins and all subprocess descendants. |

A conformance report is per resource and operation. A harness may be L3 for
filesystem reads, L2 for file writes, and L1 for strings; it must not collapse
those into a single misleading badge.

## Work tracker

- [x] Empty repository initialized with the intended GitHub remote.
- [x] Initial harness landscape and incident research recorded.
- [x] Draft YAML format and JSON Schema.
- [x] Collision-free `.aiignore.yaml` structured filename with exact
      `.aiignore` reserved for deployed gitignore-style compatibility.
- [x] Initial parser and deterministic policy-decision engine.
- [x] CLI for validation, decisions, filtering, Codex compilation, and Gemini
      CLI context/settings compilation.
- [x] Codex plugin scaffold and adapter contract.
- [x] Gemini CLI extension, `BeforeTool` adapter, and compilation-gap reporting.
- [x] Language-neutral conformance-vector schema and reusable CLI runner.
- [x] Versioned conformance manifest binding the exact specification, schemas,
      vector packs, and harness plan by canonical URI and SHA-256.
- [x] Canonical Pages build, package payload gate, signed-tag release workflow,
      checksums, SBOM, artifact attestation, and npm trusted-publisher path.
- [x] Deterministic parser/decision robustness fuzzing with checked-in seeds,
      replay instructions, and a scheduled rotating-seed extended campaign.
- [ ] Validate the adapter against released Codex builds on macOS, Linux, WSL,
      and native Windows. A provisional macOS/Codex 0.144.5 result is recorded;
      the portable suite passes Debian containers on Node 20 and 24, but live
      a local no-model rerun also reproduced the same scoped result on Codex
      0.144.5. Linux bubblewrap, WSL2, and native Windows sandbox backends
      remain outstanding.
- [ ] Add Qwen Code, OpenHands, and generic MCP adapters.
- [x] Add a detached Ed25519 conformance-signature envelope and verifier that
      requires out-of-band identity and public-key trust pins.
- [ ] Obtain independent security review and threat-model review.
- [ ] Stabilize v1.0 through a public RFC process and neutral governance.

## Open design questions

1. Whether v1.0 should permit nested `.aiignore.yaml` files or require one policy
   root. The alpha requires one explicit root to avoid hidden policy weakening.
2. How administrator and repository policies compose monotonically across
   harnesses with different configuration hierarchies.
3. Whether standard secret detectors should be normative, versioned profiles,
   or implementation-supplied extensions.
4. How to attest that a running harness is enforcing the exact policy digest.
5. Whether a future version should model derived-content provenance explicitly,
   or keep archives, VCS objects, caches, and diagnostics as separately named
   resources covered by adapters and content-boundary rules.
