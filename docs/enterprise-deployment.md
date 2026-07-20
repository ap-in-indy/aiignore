# Enterprise deployment profile

This profile describes a defensible deployment pattern for evaluating the
experimental draft in an organization. It does not turn the reference CLI into
a sandbox and does not create a blanket compliance claim.

## Control architecture

```text
administrator-controlled policy + expected digest
                    |
                    v
      launcher filters environment and pins
         policy path, root, and digest
                    |
                    v
     harness hooks mediate declared tool paths
                    |
          +---------+---------+
          |                   |
          v                   v
  OS filesystem sandbox   egress proxy/firewall
          |                   |
          +---------+---------+
                    v
       secret-free audit and conformance evidence
```

The repository is untrusted in this model. Store mandatory policy outside the
checkout, mount it read-only, and prevent the harness identity from changing
the policy, adapter, launcher, proxy configuration, or audit sink.

## Required controls

1. Remove long-lived credentials from the agent runtime. Prefer short-lived,
   task-scoped credentials issued through a broker.
2. Use an administrator policy outside the repository. Do not compose it with
   repository policy until monotonic composition is standardized and tested.
3. Pass the workspace root explicitly so external policy paths do not change
   file-pattern meaning.
4. Pin the policy SHA-256 and exact harness, adapter, runtime, and sandbox
   versions for the session.
5. Treat every adapter error-severity gap as unenforced. Do not use
   `--allow-partial` in an enforcement gate.
6. Enforce file and network restrictions below the model and across every
   subprocess. Hooks are defense in depth, not the only boundary.
7. Inventory shell, built-in tools, MCP servers, apps, browser automation,
   search, Git, archives, caches, diagnostics, logs, redirects, and background
   services. An unmediated path invalidates the claim for that resource.
8. Send audit events to a sink the agent cannot edit. Never log policy string
   patterns, environment values, request bodies, or matched secret material.
9. Run adversarial and live conformance tests after every harness, sandbox,
   proxy, operating-system, or policy change.
10. Publish claims per resource and operation with failures and untested paths;
    never collapse the report into one “secure” badge.

## Reference launch pattern

```sh
EXPECTED_SHA256="reviewed policy digest"
export AIIGNORE_POLICY_SHA256="$EXPECTED_SHA256"

aiignore run \
  --policy /etc/aiignore/organization.aiignore.yaml \
  --root /workspaces/project \
  -- codex
```

The launcher filters inherited environment values and passes
`AIIGNORE_POLICY_PATH`, `AIIGNORE_POLICY_ROOT`, and
`AIIGNORE_POLICY_SHA256` to bundled hooks. A missing, changed, invalid, or
unreadable pinned policy fails closed. These names are reserved control-plane
variables: an inherited digest is verified as the expected pin, inherited path
and root values are discarded, and verified values are injected after policy
filtering so repository policy cannot forge or remove the attestation.

## Rollout

1. Validate policy and compilation reports in CI using synthetic fixtures.
2. Run the harness in an isolated non-production tenant with no real secrets.
3. Exercise every declared boundary and document all failures and untested
   paths in a provisional conformance report.
4. Add real workloads only after the organization accepts the scoped residual
   risks and has incident response, revocation, and rollback procedures.
5. Require a fresh, detached-verification report before promoting a harness
   version or enforcement backend.

Pin the report signer's identity and Ed25519 SPKI DER SHA-256 in managed
configuration separate from the report and signature envelope. Use
`aiignore verify-report` as a deployment gate. A mathematically valid signature
from an unpinned key is untrusted, and a trusted signature authenticates report
bytes rather than certifying mediation completeness. See
`docs/conformance-signatures.md` for signing, verification, rotation, and
revocation guidance.

## Explicitly unsupported as an enterprise claim

- Model instructions or prompt promises as the enforcement mechanism.
- Repository-controlled policy as a non-bypassable administrator control.
- A context-only ignore file presented as filesystem confidentiality.
- A package provenance attestation presented as proof that behavior is secure.
- Passing decision vectors presented as proof that every harness path is
  mediated.
