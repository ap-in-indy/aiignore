# Contributing

The project is in an RFC-oriented alpha phase. Changes to normative behavior
must include:

1. a written problem and threat scenario;
2. specification and JSON Schema updates;
3. language-neutral conformance vectors;
4. reference-engine tests;
5. compatibility and security analysis.

Run `npm run verify` before submitting a change. Security-sensitive changes
should add at least one negative or adversarial test.

Major implementation changes must add or update automated tests. Normative
changes must update the specification, schema when applicable, portable vector
revision, coverage matrix, conformance manifest, versioning analysis, and
release notes as one reviewable change. Registry changes must follow
`spec/registries.md`; specification errors must follow `spec/errata.md`. See `docs/versioning.md` and
`docs/conformance-policy.md` before changing a published surface or claim.

Run `aiignore conformance test/conformance/v0.1.json` when changing decision
semantics. Vector changes require a new `revision`; published conformance
reports must identify that exact revision.

All commits must include a Developer Certificate of Origin 1.1 sign-off whose
name and email match the commit author:

```sh
git commit -s
```

The pull-request DCO check validates every commit; adding one sign-off in a
later commit does not repair earlier unsigned commits. By signing off,
contributors make the certification in the repository's verbatim [`DCO`](DCO)
under the MIT contribution license.
