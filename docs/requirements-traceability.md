# Normative requirements traceability

The reviewed catalog at `conformance/requirements-v0.1.json` maps every
top-level section of draft 0.1 to portable artifacts, reference tests,
operational evidence, and explicit limitations. It also inventories all 151
uses of BCP 14 requirement keywords outside fenced examples.

Evidence paths resolve against the immutable release-tag source tree named by
`evidenceBaseUri`. They do not assert that every cited test is copied into the
npm package. Consumers should authenticate the release first, then inspect the
path at that exact tag.

Run the machine check with:

```sh
npm run requirements:validate
```

The validator fails when a specification section is added, removed, renamed,
or gains or loses normative language without a matching catalog update. It also
requires every cited evidence path to be a checked-in regular file, locks the
reviewed catalog bytes, and prevents sections with external enforcement
dependencies from being silently promoted to fully implemented.

## Assurance values

- `implemented` means the reference behavior has portable or direct automated
  evidence and the section does not depend on a live enforcement boundary.
- `implemented-with-external-limits` means reference behavior is tested, but a
  complete claim also requires operating-system, harness, proxy, audit-sink, or
  independent implementation evidence named in `limitations`.
- `process` means the section defines governance, versioning, security-review,
  or publication controls whose completion depends on an operational event.
- `informational` means the section frames scope or external references rather
  than defining directly executable behavior.

This is section-level traceability, not a claim that 151 independent test cases
prove 151 clauses. A single normative paragraph can require multiple tests, and
one portable vector can support multiple related requirements. Reviewers should
use the catalog to locate evidence, then inspect the normative text and cited
artifact together. The catalog cannot convert self-authored evidence into an
independent implementation or security assessment.

Changing an assurance value, reducing evidence, or removing a limitation is a
reviewed assurance-policy change. Normative changes must also update schemas,
portable vectors, the coverage matrix, release notes, and the content-addressed
conformance manifest as required by `CONTRIBUTING.md`.
