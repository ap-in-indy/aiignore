# Getting started safely

This guide is the shortest path from an empty repository to a reviewed
`.aiignore.yaml` policy. It does not turn the policy file or reference CLI into
a sandbox. Enforcement still belongs to the harness, operating-system sandbox,
or network control that mediates the requested resource.

## 1. Create a starting policy

From a source checkout:

```sh
npm ci --ignore-scripts
npm run build
node dist/cli.js init
```

After the package is published, pin the exact prerelease:

```sh
npm install --ignore-scripts --save-dev aiignore@0.1.0-alpha.1
npx aiignore init
```

`init` refuses to overwrite an existing path. The generated profile blocks
common credential files and environment-variable names and redacts common
secret shapes. It is a conservative starting point, not knowledge of your
organization's data model.

## 2. Run the readiness diagnostic

```sh
npx aiignore doctor
```

The report answers three different questions separately:

- **Policy valid:** the file parsed and passed schema/semantic validation.
- **Adapter exact or partial:** a vendor configuration can or cannot represent
  the policy without known semantic gaps.
- **Deployment enforcement:** always `NOT ESTABLISHED` by this command. Only a
  tested harness/sandbox deployment and scoped conformance evidence can
  establish it.

`doctor --json` emits the versioned, secret-safe
`schema/readiness-report.schema.json` contract. It never includes policy paths,
patterns, rule IDs, candidate values, or adapter gap messages. This makes the
summary appropriate for ordinary CI logs, but the full policy and detailed
adapter compilation report may still be sensitive.

The JSON field `deploymentEnforcement` is fixed to `"not-established"`; no
option can promote it. Exit status 0 means that the report was generated from a
valid policy, not that a deployment passed a readiness or security gate.

## 3. Review the defaults first

Missing defaults are `allow`. A common starting posture is:

```yaml
defaults:
  files: allow
  environment: allow
  network: deny
  strings: allow
```

This keeps ordinary workspace work usable while requiring explicit network
destinations. Organizations with fully enumerated workspaces may choose file or
environment default deny, but must add deliberate allow rules and test every
required operation.

## 4. Check representative decisions

Use synthetic names and URLs rather than real secrets:

```sh
npx aiignore check file secrets/example.txt --operation read
npx aiignore check env EXAMPLE_TOKEN
npx aiignore check network https://example.invalid/upload
printf 'synthetic-token-marker' | npx aiignore scan --scope tool_output
```

File patterns match the complete path relative to the policy root. `name.txt`
matches only the root entry; `**/name.txt` matches it at the root and at any
descendant depth. An `except` disables only its containing rule and does not
implicitly allow the candidate.

## 5. Inspect the target adapter

```sh
npx aiignore compile codex --report
npx aiignore compile gemini --report
```

Exit status `4` means the export is partial. Do not use `--allow-partial` in an
enforcement gate. A generated ignore file normally controls context selection,
not direct shell, browser, MCP, filesystem, or network access.

## 6. Test without real credentials

Start in a disposable workspace and non-production tenant. Remove long-lived
credentials from the process, use synthetic fixtures, and exercise shell,
built-ins, subprocesses, Git, archives, browser/network tools, MCP/apps,
redirects, logs, and diagnostics. A denied direct file read does not prove that
an archive, VCS object, cache, or remote copy is inaccessible.

For an organization-managed rollout, continue with
[`enterprise-deployment.md`](enterprise-deployment.md). Harness authors should
use [`implementers.md`](implementers.md) and the complete content-addressed
conformance bundle.
