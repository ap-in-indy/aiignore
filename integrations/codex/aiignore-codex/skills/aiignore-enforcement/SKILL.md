---
name: aiignore-enforcement
description: Validate a repository .aiignore.yaml policy, compile its enforceable filesystem and network rules into a Codex permission profile, and report gaps without overstating assurance.
---

# aiignore enforcement for Codex

Use this workflow when a repository contains `.aiignore.yaml` or the user asks to
inspect its AI access policy.

1. Run `aiignore validate .aiignore.yaml` from the policy root.
2. Run `aiignore compile codex --policy .aiignore.yaml --report`.
3. Treat every reported error gap as unenforced. Do not claim sandbox-level
   protection for that resource.
4. Install the generated TOML only through the user's or administrator's Codex
   configuration workflow. Repository-local hooks are supplemental and do not
   replace permission profiles.
5. Re-run validation after changes and compare the policy SHA-256.

The plugin's `PreToolUse` hook checks direct path/URL fields, tool-input string
rules, and referenced environment-variable names. Current Codex hook coverage
does not include every built-in read/search path, so filesystem confidentiality
must come from the compiled OS-enforced permission profile.
