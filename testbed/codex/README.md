# Live Codex enforcement test

`run-live.mjs` launches `codex sandbox` through the environment-filtering
reference launcher and does not call a model or consume account quota. It is
not part of ordinary CI because it depends on a locally installed Codex version
and OS sandbox backend.

The live runner creates a temporary Git repository containing:

- a denied `private/canary.txt`;
- an allowed `public.txt`;
- a symlink to the denied file where the platform permits it;
- a committed Git-history copy and a pre-existing tar archive containing the
  private canary;
- a dropped `AIIGNORE_CANARY_TOKEN` environment variable;
- a real loopback capture endpoint that should receive no forbidden request.

The runner attempts each access through processes inside the real sandbox. The
run passes only when exit status and captured output prove denial and the
private canary never appears. Failure diagnostics replace canaries before
writing them to the terminal.

Before each enforced case, the runner performs the same operation outside the
sandbox and requires it to succeed against the same fixture. A missing command,
broken symlink, unreachable capture server, or invalid fixture therefore fails
the case instead of masquerading as an enforcement denial.

The runner writes a machine-readable report to
`test-results/codex-live/conformance.json` even when a case fails. Review that
artifact before promoting it into `conformance/results`; failed results must not
be deleted or converted into `notTested` entries.

Executable cases must have an exact ID and expected-effect match in
`conformance/vectors/codex-sandbox-v0.1.json`. The report records that plan's
canonical URI, revision, and SHA-256 plus the separate runner SHA-256.

The current macOS/Codex 0.144.5 run intentionally exits nonzero because an
allowed pre-existing archive can reproduce protected bytes. Direct, shell,
symlink, Git-history, environment-inheritance, and real loopback-capture cases
pass. This distinguishes path isolation from content-provenance control.

Run it after building:

```sh
npm run build
node testbed/codex/run-live.mjs
```

One local pass is evidence for that exact Codex and OS version, not a portable
conformance result. Platform-specific trace capture and pinned versions remain
required before publication.

This explicit hold prevents an unverified alpha script from producing a false
security badge.
