# Existing ignore and exclusion formats

Research date: 2026-07-15; compatibility decision updated 2026-07-16. This
comparison explains why aiignore uses a structured policy without reusing an
incompatible deployed filename.

| Tool | Mechanism | Syntax | Documented boundary |
| --- | --- | --- | --- |
| JetBrains AI Assistant | `.aiignore` | `.gitignore`-like paths | AI Assistant file/folder processing; JetBrains explicitly says its Claude Agent does not honor it |
| Qwen Code | `.qwenignore`, plus `.agentignore` and `.aiignore` compatibility names | `.gitignore`-like paths | Tools that support the feature, such as bulk reads; other services can still see files |
| Gemini Code Assist | `.aiexclude`, optionally `.gitignore` | `.gitignore`-like paths | Context exclusion for generation, completion, transformation, chat, and enterprise customization |
| Continue | `.continueignore` | `.gitignore` rules | Codebase indexing/context exclusion |
| Cursor | `.cursorignore` and `.gitignore` | `.gitignore`-like paths | Context/indexing exclusion; CLI permissions are a separate control |
| GitHub Copilot | Repository/organization/enterprise content exclusions | YAML settings with `fnmatch` paths | Selected IDE features; Copilot CLI, cloud agent, and IDE Agent mode are documented as unsupported |

Sources:

- [JetBrains project settings](https://www.jetbrains.com/help/ai-assistant/settings-reference-project-settings.html)
- [JetBrains Claude Agent limitation](https://www.jetbrains.com/help/ai-assistant/claude-agent.html)
- [Qwen Code ignore files](https://qwenlm.github.io/qwen-code-docs/en/users/configuration/qwen-ignore/)
- [Gemini Code Assist `.aiexclude`](https://developers.google.com/gemini-code-assist/docs/create-aiexclude-file)
- [Continue `.continueignore`](https://docs.continue.dev/reference/deprecated-codebase)
- [Cursor folder/context ignore behavior](https://docs.cursor.com/context/%40-symbols/%40-folders)
- [GitHub Copilot content exclusions](https://docs.github.com/en/copilot/how-tos/configure-content-exclusion/exclude-content-from-copilot?tool=vscode)

## Lessons incorporated into the draft

1. `.aiignore` and `.agentignore` already have compatibility recognition with
   gitignore-style syntax. Reusing `.aiignore` for YAML would create a silent,
   security-relevant format collision, so the structured policy uses
   `.aiignore.yaml` and reserves `.aiignore` for compatibility.
2. Gitignore syntax is familiar and remains the file-pattern subset, but it
   cannot unambiguously express environment handling, URL canonicalization,
   string-boundary scopes, effects, priorities, or assurance levels.
3. "Ignored" often means "not indexed" or "not read by selected tools," not
   "unreadable by the agent process." The specification therefore requires
   per-resource conformance levels.
4. Feature coverage can differ inside one product. Conformance attaches to a
   harness surface and version, not only a vendor name.
5. Compatibility files should be import/export targets. They cannot serve as
   the normative representation when an export would silently lose policy.

## Serialization decision

Draft 0.1 uses `.aiignore.yaml` with restricted YAML 1.2 plus JSON Schema because it provides comments
and readable structured rules across all resource types. To reduce YAML's
well-known parser and object-construction risks, the specification admits only
the JSON data model and forbids anchors, aliases, merge keys, tags, duplicate
keys, multiple documents, and unknown properties.

A line-oriented DSL was considered, but sections, escaping, actions, scopes,
and exceptions quickly become an underspecified programming language. JSON was
considered, but the lack of comments is a substantial policy-maintenance cost.
TOML remains a plausible alternative; YAML was selected primarily for existing
policy-tooling and JSON Schema interoperability, not because it is intrinsically
safer.
