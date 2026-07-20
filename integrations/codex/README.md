# Codex adapter

The `aiignore-codex` plugin provides supplemental `PreToolUse` decisions. An
npm-package installation uses its package-relative `dist/cli.js`; a standalone
or managed hook installation must set `AIIGNORE_CLI_JS` to the reviewed,
absolute `dist/cli.js` path. The hook never selects an enforcement binary from
the workspace or `PATH`.

Relative tool paths are resolved from the `PreToolUse` event working directory;
the resulting absolute path is then evaluated relative to the separately pinned
policy root. A nested working directory never changes policy-rule meaning.

Hard filesystem and network enforcement uses a generated Codex permission
profile:

```sh
aiignore compile codex --policy .aiignore.yaml --report
```

The command exits `4` when compilation is partial unless `--allow-partial` is
provided. Never discard the gap report when making a conformance claim.

The minimum target for permission profiles is Codex `0.138.0`. Do not combine a
generated permission profile with legacy `sandbox_mode` or
`sandbox_workspace_write` settings; Codex selects one permission system rather
than composing them. Test the exact client version and operating-system backend
before deployment.

Launch Codex through the filtered environment boundary as well as the compiled
permission profile:

```sh
aiignore run --policy .aiignore.yaml -- codex
```

## Enterprise-managed installation

Plugin hooks require user review and trust and can be disabled. They are not an
administrator boundary. Enterprise deployments should install the hook script
outside the workspace, configure it as a managed `PreToolUse` hook through
`requirements.toml`, pin `[features].hooks = true`, and set
`allow_managed_hooks_only = true` when unmanaged hooks must be excluded.

Use a managed permission-profile allowlist and default so users cannot select a
broader profile. The generated profile remains a draft input to that managed
configuration; review every compilation gap and remove error-severity gaps
before making a scoped claim.

Current Codex documentation: [hooks](https://learn.chatgpt.com/docs/hooks),
[permission profiles](https://learn.chatgpt.com/docs/permissions), and
[managed configuration](https://learn.chatgpt.com/docs/enterprise/managed-configuration).
