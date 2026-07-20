# Harness selection (2026-07-15)

This research chooses the first adapter, not the owner of the standard. The
format, decision engine, schema, and conformance vectors remain harness-neutral.

## Candidates

Repository metadata was captured from the GitHub API on 2026-07-15. Stars are
only an adoption proxy and can change.

| Harness | Stars | License | Primary language | Relevant security surface |
| --- | ---: | --- | --- | --- |
| Gemini CLI | 106,002 | Apache-2.0 | TypeScript | Extensions, hooks, policy engine, multiple sandboxes |
| OpenAI Codex | 98,425 | Apache-2.0 | Rust | Native OS sandbox, permission profiles, hooks, managed policy |
| OpenHands | 80,872 | Source reports no SPDX assertion | Python | Containerized runtime and agent SDK |
| Cline | 64,687 | Apache-2.0 | TypeScript | IDE agent, hooks/permissions |
| Goose | 51,240 | Apache-2.0 | Rust | MCP-first extensibility |
| Aider | 47,401 | Apache-2.0 | Python | Mature CLI and repository map |
| Continue | 34,892 | Apache-2.0 | TypeScript | `.continueignore`, IDE context pipeline |
| Qwen Code | 26,035 | Apache-2.0 | TypeScript | Reads `.aiignore` and `.agentignore` as compatibility files |

Sources: the respective GitHub repositories for
[Codex](https://github.com/openai/codex),
[Gemini CLI](https://github.com/google-gemini/gemini-cli),
[OpenHands](https://github.com/OpenHands/OpenHands),
[Cline](https://github.com/cline/cline),
[Goose](https://github.com/aaif-goose/goose),
[Aider](https://github.com/Aider-AI/aider),
[Continue](https://github.com/continuedev/continue), and
[Qwen Code](https://github.com/QwenLM/qwen-code).

## Decision

Use **OpenAI Codex CLI as the first enforcement adapter**, while keeping the
reference engine standalone.

Reasons:

1. Its permission profiles already model `read`, `write`, and `deny`, including
   denied workspace-relative globs. Narrower rules can carve paths out of a
   writable workspace.
2. The OS-enforced sandbox applies to spawned commands, addressing the common
   bypass where an agent uses `cat`, `rg`, a test runner, or another subprocess
   after a built-in read tool respected an ignore file.
3. Network rules are allowlist-first, support exact and wildcard domains, and
   distinguish public, loopback, link-local, and private destinations.
4. Managed requirements can pin permission profiles and hooks so a repository
   or local user cannot silently weaken enterprise policy.
5. The implementation is Apache-2.0 and uses Rust, a suitable future target for
   an in-process reference-engine port.

Codex permission profiles are currently documented as beta, so the adapter must
pin a minimum tested version and fail closed on unsupported configuration.

## Second adapter: Gemini CLI

Gemini CLI is highly adopted and has strong extension, hook, policy-engine, and
sandbox concepts, so it is now the second reference adapter. The implementation
generates a dedicated context-ignore file, a conservative environment-redaction
settings fragment, and an extension `BeforeTool` hook. Gemini's ignore mechanism
is L1 context filtering rather than a direct filesystem boundary: the documented
`read_file` and `write_file` interfaces do not take ignore-filter arguments.

The extension hook returns Gemini's structured denial response for direct path,
URL, environment-reference, and tool-input checks. It remains L2 defense in
depth because shell commands and alternate tools can encode resources in ways a
generic argument walker cannot reliably recover. Strong filesystem or network
claims therefore require an enabled, independently tested sandbox or proxy.

Gemini's official policy-engine documentation also currently warns that the
workspace policy tier is non-functional (issue `#18186`). The adapter does not
silently depend on that tier.

Sources:

- [Codex sandbox implementation](https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/README.md)
- [Codex hooks documentation](https://learn.chatgpt.com/docs/hooks)
- [Gemini CLI policy engine](https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/policy-engine.md)
- [Gemini CLI sandboxing](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/sandbox.md)
- [Gemini CLI hooks](https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/index.md)
- [Gemini CLI file tools](https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/file-system.md)
- [Gemini CLI configuration](https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md)

## Important adapter limitation

Codex hooks are supplemental, not the hard filesystem boundary. Current public
issues document incomplete `PreToolUse` coverage for built-in `read_file` and
`grep` paths. Therefore the adapter compiles file/network rules to a permission
profile and never claims L3 based only on hooks.

Source: [Codex issue #18491](https://github.com/openai/codex/issues/18491).

The strengthened local test also found that path isolation is not content
provenance: a pre-existing allowed tar archive containing bytes copied from a
denied path remains readable. The versioned provisional report records this as
a failed case. A sanitized checkout, archive policy, or content-boundary scanner
is required when copied historical material is in scope.
