# Adoption guide

## For harness authors

1. Parse and validate policy before indexing or processing repository content.
2. Implement the language-neutral decision vectors.
3. Map every data path: built-ins, shell, MCP/apps, Git, archives, diagnostics,
   browser, network, logs, and transcripts.
4. Enforce filesystem and network denial below the model wherever possible.
5. Publish conformance per resource and operation, with known gaps.
6. Fail closed when the policy cannot be applied at the claimed level.

The baseline and security vector packs are validated by
[`schema/conformance-vectors.schema.json`](../schema/conformance-vectors.schema.json).
Run the reference oracle against both `test/conformance/v0.1.json` and
`test/conformance/security-v0.1.json`; independent implementations should
consume the same JSON and compare every `effect`, `ruleId`, and optional
redacted `output`.

Portable engine output must validate against
[`schema/decision.schema.json`](../schema/decision.schema.json). Audit-capable
enforcement points must emit the deliberately minimal event in
[`schema/audit-event.schema.json`](../schema/audit-event.schema.json) before
allowing an audited boundary crossing. Keep richer operational correlation in a
separate protected telemetry system; do not extend the portable event with
paths, URLs, values, prompts, or matched patterns.

## For organizations

Treat repository `.aiignore.yaml` as developer policy, not administrator policy.
Distribute mandatory controls outside the repository, protect them from agent
writes, and pin the expected policy digest. Remove long-lived secrets from the
agent runtime even when a file or string rule would normally catch them.

For a complete control architecture, pinned launch example, and rollout gates,
use the [enterprise deployment profile](enterprise-deployment.md).

## Suggested rollout

1. Run `aiignore doctor` and retain its secret-safe JSON summary with the
   reviewed policy digest; treat `deploymentEnforcement: not-established` as a
   required reminder, not a failure that can be waived by renaming it.
2. Start in audit mode and inventory false positives without logging values.
3. Enforce environment dropping and network default-deny.
4. Add filesystem deny rules under a real sandbox.
5. Add content redaction only as defense in depth.
6. Run adversarial tests on every harness or sandbox upgrade.
7. Rotate any credential that may have been visible before enforcement.

## Compatibility exports

Adapters may generate vendor formats such as `.cursorignore`, `.aiexclude`, or
Codex permission profiles. The Gemini CLI adapter generates a separate
`.aiignore.generated.geminiignore`; `.aiignore` remains available to tools that
already interpret it as gitignore syntax. Generated files must carry the source policy
digest and a machine-readable gap report. An export is invalid if it silently
widens access.
