# Governance and standardization path

## Current phase

The project is maintainer-led while the 0.x threat model and conformance format
are unstable. Normative changes require a public proposal, tests, and an
explicit compatibility/security analysis.

Published bytes are immutable. The authoritative errata index and closed
registry policy are part of the versioned conformance bundle.

The operational proposal lifecycle and template live in [`rfcs/`](../rfcs/).

## Proposed maturity stages

1. **Experimental draft:** prove the resource model and adapters; no stable
   compatibility promise.
2. **Public RFC:** freeze terminology, publish at least two independent parser
   implementations, and solicit harness/security-vendor review.
3. **Candidate standard:** require two interoperable harness implementations,
   signed conformance reports, independent security assessment, and a defined
   errata process.
4. **1.0 standard:** establish neutral multi-organization governance and a
   trademark/conformance policy before claiming an industry standard.

## Change requirements

Normative proposals must state the threat scenario, backwards compatibility,
canonicalization behavior, failure mode, and conformance vectors. Security
properties cannot be accepted solely because one harness happens to implement
them.

## Neutral home

Before 1.0, maintainers should evaluate donation to an appropriate neutral
standards or open-source foundation. No current foundation affiliation is
claimed. Names such as the Agentic AI Foundation should not be used in project
marketing without formal acceptance.

## Intellectual property and marks

The current MIT/DCO posture and its limitations are documented in
[`intellectual-property.md`](intellectual-property.md). Candidate-standard
advancement requires an explicit standards IPR policy and independent legal
review. No current project name or conformance wording is a certification mark.
