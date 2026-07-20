# Adversarial test results — through 2026-07-16

This review challenged the draft 0.1 parser and reference engine at trust
boundaries where permissive library behavior could weaken the specification.
Every confirmed reference-implementation defect below has a regression test.

| Probe | Initial result | Required behavior and remediation | Regression evidence |
| --- | --- | --- | --- |
| Regex replacement `$1` and `$&` | RE2JS expanded captures and could reproduce the matched secret | Quote all non-literal replacement strings so replacement text is literal | `test/patterns.test.ts`, `test/engine-string.test.ts`, `options-v0.1.json` |
| `https://*.127.0.0.1/**` and wildcard IPv6 | Wildcard IP literals parsed as host wildcards | Reject wildcard modes when the normalized host is an IP literal | `test/patterns.test.ts`, parser vector `network-wildcard-ip` |
| Network path `?` | Parser treated the glob token as a forbidden query | Define policy `?` as a one-character path wildcard; continue ignoring candidate queries | `test/patterns.test.ts`, complete parser vector |
| File pattern `private/` against `private` | Descendants matched but the directory itself did not | A trailing slash matches the directory and all descendants | `test/patterns.test.ts` |
| Inline consecutive `*` | Specification wording implied every `**` crossed separators | Align the normative text with gitignore: only complete double-star segment positions cross `/` | `test/patterns.test.ts` |
| Candidate URL ending in `#` | WHATWG parsing erased the empty fragment marker | Reject any lexical fragment marker, including an empty fragment | `test/patterns.test.ts` |
| Ports `0443` and `99999` | Leading-zero defaults did not canonicalize; out-of-range ports were accepted in policy patterns | Parse decimal ports, enforce 0–65535, remove leading zeroes and scheme defaults | `test/patterns.test.ts`, parser port vectors |
| Invalid sensitive regex source | The RE2 error embedded the configured pattern | Return a generic invalid-RE2 error without the source | `test/parser.test.ts` |
| Decision vectors | Only effect, rule id, and selected output were checked | Support `matched` and `appliedRuleIds`; always verify resource, digest, and non-empty reason | `options-v0.1.json`, `src/conformance.ts` |
| Negated string-glob classes | `[!A-C]` was copied into regex syntax and inverted incorrectly | Translate the portable glob negation marker to RE2 `[^A-C]` and publish positive/negative vectors | `test/patterns.test.ts`, `options-v0.1.json` |
| Ambiguous URL separators | WHATWG parsing normalized single/triple slashes and backslashes before policy matching | Require lexical `scheme://authority` form and reject backslashes before parsing | `test/patterns.test.ts`, security vectors |
| Parser portability | Invalid syntax existed only in TypeScript unit tests | Publish a language-neutral parser-vector schema, 50 cases, runner, and CLI command | `schema/parser-vectors.schema.json`, `test/parser-conformance/v0.1.json` |
| Coverage accounting | Only imported source files were counted, omitting the CLI | Instrument `src/**/*.ts`, add CLI/adapter tests, and raise thresholds | `vitest.config.ts`, coverage run |
| `.aiignore` YAML collision | JetBrains and Qwen already parse the exact filename as gitignore syntax | Use `.aiignore.yaml` for structured policy and reserve `.aiignore` for compatibility | specification section 2, loader and parser tests |
| Windows case aliases | File matching had no explicit case-insensitive decision mode | Add ASCII-only case folding and portable file/environment cases | security vectors and engine tests |
| Encoded URL separators | `%2f`, `%5c`, malformed escapes, and control whitespace could be interpreted differently downstream | Normalize escape case and reject ambiguous encodings before decisions | security/parser vectors and network tests |
| Zero-width redaction | Contextual assertions such as `\\b` evaded an empty-input probe and had engine-dependent replacement behavior | Reject every matcher capable of a zero-length span and cap output bytes and replacement counts | parser vectors and pattern tests |
| External administrator policy | Bundled hooks rediscovered repository policy instead of honoring the pinned launcher path/root | Propagate and enforce policy path, workspace root, and digest; fail closed if missing | CLI tests and hook testbed |
| Conformance provenance | Reports omitted source, runner, and vector digests and could use `verified` without a signature | Require exact provenance fields and detached verification evidence for verified status | report schema and schema tests |
| Package executable mode | TypeScript emitted the CLI as non-executable in the tarball | Set mode after build and fail package validation on payload or mode drift | `prepare-dist.mjs`, `validate-package.mjs` |
| Mutable loaded policy | Callers could mutate parsed effects after hashing and receive changed decisions under the old digest | Deep-freeze the parsed data model and expose readonly policy types | `parser.test.ts` |
| Policy loader path race | The loader inspected a pathname and later reopened it, allowing identity or symlink replacement between operations | Open with no-follow where available, compare file identity, and reject snapshot changes during the bounded read | `parser.ts`, loader tests |
| Network authority normalization | WHATWG parsing silently discarded query/control/backslash suffixes in policy authorities | Reject lexically ambiguous authority text before hostname normalization | parser vectors and `patterns.test.ts` |
| String overlap ordering | The prose did not freeze the match set or pattern order before redaction | Match rules against the original candidate, then apply rules by precedence and patterns by source order | options vectors and `engine-string.test.ts` |
| Codex default-deny compilation | Environment/string default deny could produce an incorrect `exact: true` report when no explicit rules existed | Emit error gaps for both unenforced defaults | `codex-adapter.test.ts` |
| Live test-plan digest | The first Codex report hashed baseline decision vectors rather than the sandbox scenarios it executed | Withdraw the report, publish a harness-vector schema and exact plan, and bind every executable case by ID/expectation | `harness-vectors.test.ts`, Codex live runner |
| False-positive sandbox denial | Any command failure, including a missing symlink or broken fixture, could satisfy a deny case | Require the identical unsandboxed control operation to succeed before counting the enforced denial | Codex live runner |
| Environment diagnostic output | `filter-env --emit-values` could print every retained value into CI logs | Remove raw-value output and report variable names grouped by policy action only | `cli.test.ts` |
| Installed npm binary | The entry-point check compared the npm symlink path to the real module path and silently exited without running | Resolve both paths before main-module comparison and execute a symlinked CLI in package validation | `validate-package.mjs`, installed-tarball smoke |
| Cross-platform vector hashes | Windows checkout converted JSON vectors to CRLF, so exact SHA-256 report binding differed from canonical LF bytes | Enforce LF for repository text with `.gitattributes` and keep hashing exact bytes | Windows CI and `harness-vectors.test.ts` |
| Consumer TypeScript declarations | Public declarations referenced `Buffer` and `NodeJS.ProcessEnv` without installing `@types/node` for consumers | Use `Uint8Array` and ordinary string records, then compile a clean consumer with `types: []` | `validate-artifact.mjs` |
| Environment object keys | A variable named `__proto__` could alter ordinary result-object prototypes instead of being retained and audited as an own property | Store filtered values and decisions in null-prototype records | `engine-environment.test.ts` |
| Composed string-matcher work | Many linear-time patterns could repeatedly scan one large boundary value and cause policy-driven CPU exhaustion | Charge a 128 MiB deterministic cumulative byte-work budget and fail closed | limits vectors and engine tests |
| Mutable public policy state | A caller could alter wrapper metadata or exported enum arrays after parsing and change decisions under a stale digest | Freeze parsed wrappers and public enums; snapshot engine metadata | parser and coverage-contract tests |
| Unknown runtime enum values | JavaScript callers could pass misspelled operations/scopes and fall through to default allow | Validate public API inputs and publish stable fail-closed diagnostics | security vectors and engine tests |
| File/environment/network matcher amplification | Large candidates composed with thousands of patterns could exceed vendor hook timeouts | Enforce normative candidate and cumulative work budgets for every resource | limits vectors and engine tests |
| Hook event amplification | Deep or many-candidate tool inputs reset per-decision budgets repeatedly | Bound traversal depth, nodes, candidate count, environment references, and aggregate candidate bytes | adapter tests |
| Hook wrapper child mismatch | Exit `3` with empty or conflicting output could be translated into vendor success | Use a package-pinned CLI module and accept only status-consistent target-specific payloads | `integration-hooks.test.ts` |
| Network hostname reinterpretation | Percent-encoded and invalid DNS labels were normalized into broader valid hosts | Define lexical DNS/IDNA rules and reject parser reinterpretation | parser/security vectors and pattern tests |
| Conformance artifact encoding | Replacement UTF-8 decoding allowed malformed JSON bytes to diverge across implementations | Require fatal UTF-8 decoding for vector runners and the conformance manifest | runner and manifest tests |
| Production license labels | Editable lockfile fields could conceal an installed package's actual license | Traverse installed production manifests and reject lock/install metadata drift | `license-validation.test.ts` |
| Audit effect delivery | Launcher and hook paths computed audit decisions without emitting an event | Emit candidate-free JSON Lines events before child launch and from hook evaluation | CLI tests |
| Hook working-directory drift | Relative tool paths were evaluated as if the event working directory were the policy root, missing nested policy paths | Resolve against the event working directory, then evaluate the absolute result relative to the pinned policy root | adapter and CLI tests |
| Terminal `/**` zero segments | The matcher required a descendant even though the draft says a terminal double-star may consume zero segments | Match both the directory/path base and descendants for file and network patterns | security vectors and `patterns.test.ts` |
| File growth after size inspection | Policy and vector readers could allocate a file that grew after the initial metadata check | Read at most the normative limit plus one byte before rejecting and verify the opened snapshot | `safe-file.test.ts` and loader tests |
| Empty policy digest pin | An explicitly supplied empty digest was treated as if no pin had been supplied | Only `undefined` means unpinned; every supplied non-matching value fails closed | parser and CLI tests |
| Bulk resource arrays | Gemini `read_many_files` supplies `paths` as an array, but hook traversal only collected scalar singular path fields | Collect bounded strings below singular or plural path and URL fields for both supplemental hooks | adapter tests |
| Codex network default allow | The compiled profile blocked local/private destinations while reporting an exact portable default-allow translation | Emit an error-severity semantic-change gap and refuse `exact: true` | `codex-adapter.test.ts` |
| Mutating/discovery tool aliases | Delete, move, rename, and listing tool names could be classified as reads and miss operation-scoped rules | Conservatively classify common mutation and discovery verbs and test both adapters | adapter tests |

## Result after remediation

- 107 language-neutral decision vectors cover every resource effect, all five
  file operations, all four network schemes, default deny, read-only, all 11
  string scopes, precedence, exceptions, and composed redaction.
- 56 language-neutral parser vectors cover the complete syntax surface plus
  unsafe YAML, schema errors, encodings, identifiers, priorities, options, and
  malformed pattern families.
- 253 reference tests pass with all source files included in coverage. The
  2026-07-16 local result is 95.07% statements, 86.72% branches, 99.10%
  functions, and 96.16% lines.
- A deterministic extended robustness campaign with seed `0x20260716` passes
  25,000 policy-parser mutations and 25,000 decision-candidate mutations after
  replaying the exact parser corpus and complete decision surface.

These results support exhaustive coverage of the enumerated draft 0.1 syntax
and options in the reference implementation. They are not a proof that every
possible input string has been tested.

## Enforcement cases still requiring harness evidence

The reference engine cannot establish end-to-end mediation by itself. A
harness conformance claim still needs separate tests for redirects, DNS
rebinding, symlinks and platform aliases, MCP/apps/browser/web tools,
subprocess inheritance, pre-existing archives and VCS objects, full model
sessions, and each supported native OS/sandbox backend. The live Codex testbed
currently records the pre-existing archive case as readable by design; that is
an explicit provenance limitation, not a parser exception.
