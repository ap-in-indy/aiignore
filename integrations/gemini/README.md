# Gemini CLI adapter

The `aiignore-gemini` extension installs a supplemental `BeforeTool` hook for
direct path, URL, environment-reference, and tool-input string decisions. The
hook emits Gemini CLI's structured `deny` response and fails closed if policy
evaluation fails.

An npm-package installation uses its package-relative `dist/cli.js`; a
standalone extension must set `AIIGNORE_CLI_JS` to the reviewed, absolute CLI
module path. The hook never selects an enforcement binary from the workspace
or `PATH`.

Relative tool paths are resolved from the `BeforeTool` event working directory;
the resulting absolute path is then evaluated relative to the separately pinned
policy root. A nested working directory never changes policy-rule meaning.

Generate the context filter and settings fragment with:

```sh
aiignore compile gemini --policy .aiignore.yaml --report
```

Write the report's `ignoreFile` to its `ignoreFileName`, and merge `settings`
into the applicable Gemini CLI settings. Never discard `gaps`: Gemini ignore
files affect context/search behavior but are not filesystem sandboxes and do
not prevent a direct `read_file`, shell command, or alternate tool path.

Launch Gemini through the filtered environment boundary as well:

```sh
aiignore run --policy .aiignore.yaml -- gemini
```

For stronger filesystem and network guarantees, enable and independently test
a Gemini CLI sandbox or external policy proxy. The extension hook is a defense
in depth layer, not a sandbox-level guarantee.

The extension structure was validated with the official Gemini CLI `0.50.0`
validator on 2026-07-15:

```sh
npx -y @google/gemini-cli@0.50.0 extensions validate integrations/gemini/aiignore-gemini
```
