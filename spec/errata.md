# aiignore draft 0.1 errata

Status: **Authoritative errata index**

This file is the public index of verified errors in the immutable draft 0.1
specification bundle. There are currently **no verified errata**.

## Rules

Published specification, schema, vector, manifest, tag, and release-asset
bytes are never replaced in place. An erratum explains an error; it does not
silently mutate the artifact to which an existing digest refers.

Each report receives an identifier `E-0.1-NNNN` and records:

- status: `Reported`, `Verified`, `Rejected`, `Held for update`, or `Corrected`;
- affected immutable artifact URI and SHA-256;
- classification: `Editorial`, `Normative`, or `Security`;
- original text or machine-readable behavior;
- corrected interpretation or disposition;
- interoperability, compatibility, security, and privacy impact;
- affected schemas, vectors, implementations, adapters, and reports;
- reporter, public discussion, decision date, and reviewers; and
- the version and bundle digest in which a correction appears.

An editorial erratum may clarify wording only when it cannot change any valid
parse, decision, diagnostic, conformance result, or security claim. A normative
or security correction requires an RFC, updated portable evidence, a new
artifact digest, and an updated release. If implementations could reasonably
disagree, the issue is normative rather than editorial.

Security-sensitive reports follow `SECURITY.md` until coordinated disclosure
is safe. The eventual public entry preserves enough detail to identify affected
versions without publishing live credentials, customer data, or an unpatched
exploit unnecessarily.

Conformance reports affected by a verified erratum are withdrawn or linked to
a superseding report. A mathematically valid signature over old evidence does
not override a later erratum or withdrawal.

## Verified errata

None.

## Report an error

Use the RFC/bug intake described in `CONTRIBUTING.md`; use the private channel
in `SECURITY.md` for a potential vulnerability. Include the exact artifact URI,
SHA-256, section or JSON pointer, observed ambiguity, and a synthetic
reproducer where possible.
