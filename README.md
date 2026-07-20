# aiignore

aiignore is an experimental, harness-neutral policy specification for making
agent access to files, environment variables, networks, and sensitive strings
explicit and testable. Structured policies live in `.aiignore.yaml`.

This repository contains the draft specification, JSON Schema, TypeScript
reference implementation, conformance vectors, and experimental adapters for
OpenAI Codex and Gemini CLI.

> **Status: pre-standard alpha.** The format and APIs may change. Do not claim
> security compliance until the relevant harness passes the conformance suite
> at the enforcement level you require.

> **Filename compatibility:** JetBrains and Qwen already interpret exact
> `.aiignore` as gitignore-style path exclusions. This draft reserves that
> filename for compatibility and uses `.aiignore.yaml` for structured policy.
> Never put YAML in `.aiignore`.

## Why this exists

Existing files such as `.cursorignore`, `.aiexclude`, `.continueignore`, and
gitignore-style `.aiignore` implementations usually control indexing or
selected tools. They are useful, but they are not a portable access-control
boundary. An agent can often reach the same content through a shell command,
an environment variable, a symlink, an MCP tool, Git history, or an approved
network destination.

This proposal separates policy from enforcement and defines three conformance
levels:

1. **Context** — excluded from indexing and automatic model context.
2. **Tool** — all covered harness tools consult the policy engine.
3. **Sandbox** — filesystem and network denial is enforced below the model and
   inherited by subprocesses.

Only level 3 is intended to support a strong isolation claim, and only for the
resources a platform can enforce completely.

## Quick start

Install the exact prerelease intentionally rather than accepting future alpha
changes implicitly:

```sh
npm install --ignore-scripts --save-dev @apinindy/aiignore@0.1.0-alpha.1
npx aiignore init
npx aiignore validate
npx aiignore doctor
```

To evaluate the draft directly from source instead:

```sh
git clone https://github.com/ap-in-indy/aiignore.git
cd aiignore
npm ci --ignore-scripts
npm run build
cp profiles/recommended.aiignore.yaml .aiignore.yaml
node dist/cli.js validate
node dist/cli.js doctor
```

`aiignore init` validates the packaged recommended profile before creating the
file and refuses to overwrite any existing path or case variant of the reserved
`.aiignore` compatibility filename.

Start in audit or a non-production sandbox. Review every rule and every adapter
gap before enforcement.

For a plain-language walkthrough, common pitfalls, and the difference between
policy validity and real enforcement, see
[`docs/getting-started.md`](docs/getting-started.md).

## Example policy

```yaml
aiignore: "0.1"

defaults:
  files: allow
  environment: allow
  network: deny
  strings: allow

rules:
  files:
    - id: private-files
      effect: deny
      paths: ["**/.env*", "secrets/**", "**/*.pem"]
      except: ["**/.env.example"]

  environment:
    - id: credential-variables
      effect: drop
      names: ["*_TOKEN", "*_SECRET", "*_PASSWORD", "AWS_*", "GITHUB_TOKEN"]
      except: ["PUBLIC_*", "*_TOKEN_TTL"]

  network:
    - id: documentation
      effect: allow
      urls: ["https://docs.example.com/**", "https://registry.npmjs.org/**"]

  strings:
    - id: private-key-material
      effect: redact
      scopes: [tool_output, network_request, log]
      patterns:
        - type: regex
          value: "-----BEGIN [A-Z ]*PRIVATE KEY-----"
      replacement: "[REDACTED:private-key-material]"
```

See [`spec/aiignore.md`](spec/aiignore.md) for normative behavior and
[`examples/complete.aiignore.yaml`](examples/complete.aiignore.yaml) for a complete
policy.

[`profiles/recommended.aiignore.yaml`](profiles/recommended.aiignore.yaml) is a
conservative incident-derived starting point for credential files, ambient
secret variables, and common secret string shapes. Audit and tune it for local
false positives before enforcement.

## Reference CLI

Requires Node.js 20.19 or newer.

```sh
npm ci --ignore-scripts
npm run build
node dist/cli.js validate examples/complete.aiignore.yaml
node dist/cli.js doctor --policy examples/complete.aiignore.yaml
node dist/cli.js init --path .aiignore.yaml
node dist/cli.js check file secrets/api-key.txt --operation read --policy examples/complete.aiignore.yaml
node dist/cli.js check env GITHUB_TOKEN --policy examples/complete.aiignore.yaml
node dist/cli.js check network https://attacker.example/upload --policy examples/complete.aiignore.yaml
printf 'token=example' | node dist/cli.js scan --scope tool_output --policy examples/complete.aiignore.yaml
node dist/cli.js run --policy examples/complete.aiignore.yaml -- codex
node dist/cli.js compile codex --policy examples/complete.aiignore.yaml --report
node dist/cli.js compile gemini --policy examples/complete.aiignore.yaml --report
node dist/cli.js conformance test/conformance/v0.1.json
node dist/cli.js parser-conformance test/parser-conformance/v0.1.json
# See docs/implementers.md for complete implementation-report generation.
# See docs/conformance-signatures.md before using sign-report or verify-report.
```

All decision commands support `--json` and return exit status `0` for allow or
audit and `3` for deny/drop. Validation errors return `2`.

`run` starts a child process with dropped/redacted environment variables and
adds `AIIGNORE_POLICY_SHA256` for attestation. It does not, by itself, install
filesystem or network isolation; use a harness adapter or OS sandbox for those
resources.

The Codex compiler emits a permission profile. The Gemini compiler emits a
generated context-ignore file plus a settings fragment. Both include explicit
compilation gaps and return status `4` for a partial export unless
`--allow-partial` is supplied. Their hooks are supplemental: see the
[`Codex`](integrations/codex/README.md) and
[`Gemini CLI`](integrations/gemini/README.md) adapter guides before making an
assurance claim.

## Validation snapshot

The current release candidate passes 253 reference tests, 107 portable decision
vectors, and 56 portable parser vectors. CI covers Node 20 and 24 on Linux plus
Node 24 on macOS and Windows. Package validation checks executable mode,
required artifacts, forbidden development files, size, two-pack byte
reproducibility, and clean installed runtime/type consumption; the release
workflow adds checksums, a CycloneDX SBOM, and provenance attestation. Every
verification run also performs deterministic parser/decision robustness
fuzzing, with a larger rotating-seed campaign on every pull request and weekly
schedule. A versioned
conformance manifest binds the exact specification, schemas, and vector bytes
that comprise the draft 0.1 interoperability bundle.

Verified implementation and harness reports use a detached Ed25519 envelope. The verifier requires
the expected signer identity and public-key SHA-256 from an independent trust
channel; it never trusts the embedded identity or key by itself.

These results establish reference and decision compatibility only. They do not
prove that every execution path in a harness is mediated.

## Project documents

- [`docs/concept.md`](docs/concept.md) — goals, threat model, and roadmap
- [`docs/getting-started.md`](docs/getting-started.md) — safe first policy,
  readiness diagnostic, representative checks, and adapter review
- [`docs/architecture.md`](docs/architecture.md) — actors, components, trust
  boundaries, external interfaces, and failure modes
- [`docs/implementers.md`](docs/implementers.md) — portable implementation
  sequence, pseudocode, canonicalization, and adapter checklist
- [`docs/enterprise-deployment.md`](docs/enterprise-deployment.md) —
  administrator-controlled deployment architecture and release gates
- [`docs/dependency-management.md`](docs/dependency-management.md) — lockfile,
  license, vulnerability, provenance, and update requirements
- [`docs/fuzzing.md`](docs/fuzzing.md) — fuzz targets, invariants, reproduction,
  corpus, and security triage
- [`docs/conformance-signatures.md`](docs/conformance-signatures.md) — detached
  report signing, trust pins, verification, rotation, and revocation
- [`docs/conformance-policy.md`](docs/conformance-policy.md) — evidence classes,
  report acceptance, claim scope, correction, and withdrawal
- [`docs/versioning.md`](docs/versioning.md) — package, language, schema, vector,
  manifest, report, compatibility, and end-of-life rules
- [`docs/credential-management.md`](docs/credential-management.md) — project
  credentials, signing keys, OIDC, access, rotation, and compromise response
- [`docs/security-baseline.md`](docs/security-baseline.md) — transparent OSPS
  baseline self-assessment and unresolved controls
- [`docs/intellectual-property.md`](docs/intellectual-property.md) — current
  license, DCO, patent-policy, and trademark limitations
- [`docs/release-checklist.md`](docs/release-checklist.md) — separate private
  push, public visibility, and package-publication gates
- [`docs/maintainer-release-runbook.md`](docs/maintainer-release-runbook.md) —
  repository protections, tag signing, two-phase publication, independent
  verification, and bad-release response
- [`docs/public-hosting.md`](docs/public-hosting.md) — machine-audited GitHub
  rulesets, security products, Pages, workflow permissions, and release environment
- [`docs/test-coverage.md`](docs/test-coverage.md) — syntax, option, decision,
  CLI, and adapter coverage matrix
- [`docs/requirements-traceability.md`](docs/requirements-traceability.md) —
  machine-checked mapping from all normative sections to evidence and limits
- [`rfcs/README.md`](rfcs/README.md) — normative proposal process and template
- [`docs/research/harness-selection.md`](docs/research/harness-selection.md) —
  evidence for the first harness adapter
- [`docs/research/incidents.md`](docs/research/incidents.md) — incidents and
  derived security requirements
- [`docs/research/existing-formats.md`](docs/research/existing-formats.md) —
  comparison with vendor-specific ignore mechanisms
- [`docs/research/adversarial-test-results.md`](docs/research/adversarial-test-results.md) —
  adversarial probes, remediations, regressions, and remaining harness gaps
- [`spec/aiignore.md`](spec/aiignore.md) — normative draft specification
- [`spec/registries.md`](spec/registries.md) — closed protocol-token registry
  and allocation policy
- [`spec/errata.md`](spec/errata.md) — immutable draft errata and correction index
- [`schema/aiignore.schema.json`](schema/aiignore.schema.json) — machine-readable schema
- [`schema/decision.schema.json`](schema/decision.schema.json) — exact portable
  decision-result contract
- [`schema/audit-event.schema.json`](schema/audit-event.schema.json) — minimal
  secret-safe audit-event contract
- [`schema/readiness-report.schema.json`](schema/readiness-report.schema.json) —
  secret-safe operator diagnostic contract that cannot claim enforcement
- [`schema/implementation-conformance-report.schema.json`](schema/implementation-conformance-report.schema.json) —
  exact parser/decision interoperability-report contract, with offline complete
  manifest-membership verification in the CLI and library
- [`schema/conformance-report.schema.json`](schema/conformance-report.schema.json) —
  scoped live harness-enforcement result schema
- [`schema/conformance-signature-envelope.schema.json`](schema/conformance-signature-envelope.schema.json) —
  detached Ed25519 report-signature envelope schema
- [`schema/conformance-vectors.schema.json`](schema/conformance-vectors.schema.json) —
  language-neutral decision-vector schema
- [`schema/parser-vectors.schema.json`](schema/parser-vectors.schema.json) —
  language-neutral valid/invalid parser-vector schema
- [`schema/harness-vectors.schema.json`](schema/harness-vectors.schema.json) —
  language-neutral live harness-test-plan schema
- [`schema/conformance-manifest.schema.json`](schema/conformance-manifest.schema.json) —
  exact versioned artifact-bundle schema
- [`schema/requirements-traceability.schema.json`](schema/requirements-traceability.schema.json) —
  requirements evidence/limitation catalog schema
- [`conformance/manifest-v0.1.json`](conformance/manifest-v0.1.json) — canonical
  draft 0.1 specification/schema/vector membership and SHA-256 bindings
- [`conformance/requirements-v0.1.json`](conformance/requirements-v0.1.json) —
  machine-readable normative-section, evidence, and residual-limit inventory
- [`conformance/vectors`](conformance/vectors) — content-addressed live harness
  test plans used by machine-readable reports
- [`conformance/results`](conformance/results) — versioned provisional harness results
- [`SECURITY.md`](SECURITY.md) — vulnerability reporting and security claims
- [`security-insights.yml`](security-insights.yml) — OpenSSF Security Insights
  2.2.0 machine-readable security metadata

## Security posture

An `.aiignore.yaml` file is not intrinsically a security boundary, just as
`.gitignore` does not prevent a file from being read or force-added. A compliant
harness must mediate every path to the protected resource. See
[`SECURITY.md`](SECURITY.md) before deploying this prototype.

## License

MIT License. Contributions are accepted under the same license and use a
Developer Certificate of Origin sign-off.
