# aiignore RFC process

Normative changes start as numbered Markdown proposals in this directory. A
proposal is discussion material until its status is **Accepted**; the current
specification and schemas remain authoritative.

## Lifecycle

1. Copy `0000-template.md` to `NNNN-short-name.md` using the next available
   four-digit number.
2. Open a pull request with status **Proposed** and link an issue containing the
   threat scenario or interoperability problem.
3. Add reference-engine tests and language-neutral vectors for every normative
   behavior.
4. Obtain at least one maintainer approval and one review from an affected
   harness or independent implementer.
5. Record the decision and compatibility impact in the RFC before merging.

An RFC that allocates or changes a protocol token must update the closed
registry, language version when applicable, schemas, vectors, and conformance
bundle. A reported specification error first receives an entry under the
process in `spec/errata.md`; if conforming implementations could observe a
different outcome, correction requires a normative RFC rather than an
editorial edit.

Statuses are **Proposed**, **Accepted**, **Rejected**, **Withdrawn**, and
**Superseded**. Security fixes may be developed privately, but their final
normative effect still requires a public RFC after coordinated disclosure.

## Decision criteria

An RFC must make canonicalization, precedence, failure behavior, compatibility,
and conformance testing precise. A vendor-specific convenience is insufficient
unless it can be expressed portably or isolated behind an adapter.
