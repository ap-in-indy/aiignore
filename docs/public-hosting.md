# Public repository hosting controls

Repository files cannot prove that owner-controlled GitHub settings are active.
The reviewed desired state lives in `.github/hosting-policy.json`; the read-only
auditor compares that contract with the GitHub APIs and fails on drift.

## What is covered

The policy requires:

- public visibility, `main` as the default branch, Issues and Discussions;
- squash-only merging, signed web commits, automatic branch deletion, and
  read-only default workflow permissions that cannot approve pull requests;
- immutable releases, vulnerability alerts and fixes, private vulnerability
  reporting, CodeQL, Dependabot updates, secret scanning, and push protection;
- public HTTPS Pages deployed only through the reviewed workflow;
- an active, no-bypass `main` ruleset requiring signed commits, pull requests,
  resolved conversations, strict current-head testing, CodeQL thresholds, and
  all ten named CI/security checks pinned to the GitHub Actions app;
- an active, no-bypass release-tag ruleset that prevents `v*` update or deletion,
  plus a separate creation rule whose only bypass is the documented release
  owner's stable GitHub user ID;
- a `release` environment restricted to `v*` tags, with administrator bypass
  disabled and no stored secrets, variables, or human-review rule.

The public alpha is explicitly single-maintainer. The `main` ruleset requires a
pull request but zero human approvals; the tag creator may also dispatch the
release. This is not independent review. The compensating controls are strict
automated checks, signed commits and tags, owner-only immutable release tags,
two-phase byte equality, OIDC, attestations, and an empty release credential
store. Add non-author approval when a second trusted maintainer exists and
before claiming candidate-standard maturity.

## Audit safely

From an authenticated maintainer checkout:

```sh
npm run hosting:audit
```

The command is read-only. It does not create rulesets, change visibility,
enable products, or alter environments. Exit status `0` means every audited
setting exactly matches the checked-in policy; `1` means drift; `2` means the
required evidence could not be read or parsed.

Some endpoints, including immutable releases, require repository admin-read
authority. Run this from a maintainer workstation using `gh auth`; do not put a
personal access token in Actions. The output reports setting paths and bounded
metadata only. Environment secret and variable names are reduced to counts and
their values are never available to the auditor.

For offline testing or a separately reviewed API capture:

```sh
node scripts/audit-github-hosting.mjs --snapshot reviewed-snapshot.json --json
```

`npm run hosting-policy:validate` validates the desired-state structure during
ordinary CI without pretending that repository-side controls are active.

## Activation sequence

1. Merge the reviewed implementation into `main`. Confirm the sole maintainer
   uses phishing-resistant MFA and that `MAINTAINERS.md` accurately records the
   single-maintainer authority and continuity limitation.
2. Change visibility only after the public-visibility gate in
   `docs/release-checklist.md` is approved.
3. Enable the repository security features, Pages, immutable releases, and
   safe merge settings from the policy.
4. Open a bootstrap pull request after the workflows are present on `main` and
   let every required check complete successfully. GitHub only permits a check
   to become required after it has completed successfully in the repository
   during the preceding seven days.
5. Create the three rulesets using the exact `rulesets` objects in
   `.github/hosting-policy.json`. Do not add or broaden bypass actors; only the
   dedicated tag-creation rule has the single reviewed owner bypass.
6. Create the `release` environment with no required-reviewer rule, disable
   administrator bypass, restrict deployment to the `v*` tag pattern, and leave
   secrets and variables empty. npm publication uses OIDC trusted publishing.
7. Run `npm run hosting:audit` until it returns `0`.
8. Trigger another pull request and confirm the ruleset requires public CodeQL,
   dependency review, CI, fuzzing, DCO, and Gitleaks under the exact names in the
   policy. Run Scorecard and review its findings separately.
9. Re-run the audit before each release and after any collaborator, security,
   workflow-permission, Pages, environment, or ruleset change.

Ruleset and security-product availability may depend on GitHub plan and public
visibility. An unavailable required control is a failed gate, not permission to
silently omit it. Record an explicit, reviewed alternative before changing the
desired-state contract.
