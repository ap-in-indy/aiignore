# Maintainers

## Current maintainers

- Alex (`@ap-in-indy`) — specification editor and reference
  implementation maintainer — `alex@alexdoes.it`

Maintainers review normative changes, releases, security fixes, and conformance
claims. No vendor is currently represented and no organization endorses this
experimental draft.

The project intends to add independent implementers and harness vendors as
maintainers before advancing beyond the public RFC stage. Governance changes
follow [docs/governance.md](docs/governance.md).

## Sensitive-resource authority

The current maintainer is the sole person authorized to administer repository
settings, security advisories, release environments, package ownership,
release-signing identity, and official conformance-evidence acceptance. This is
a bus-factor and independent-review limitation, not a two-person control.

## Adding or escalating maintainers

Access is granted only after a public record of sustained, technically sound
contributions and review in the area covered by the role. Before granting
write, security, release, package, or administrative authority, maintainers
must document:

1. the role and least privilege required;
2. relevant contributions and conflict-of-interest disclosures;
3. account identity and phishing-resistant MFA readiness;
4. review of the credential and coordinated-disclosure policies;
5. approval by every existing maintainer who is not the candidate.

No contributor receives elevated access merely for affiliation with a vendor,
volume of contributions, or urgency of one release. New maintainers begin with
the narrowest practical role. Release/package administration is separate from
ordinary code review where the hosting platform permits it.

Sensitive access is reviewed before every release and at least annually. It is
removed promptly after role departure, account compromise, inactivity that
prevents responsible review, or violation of the code of conduct/security
process. Emergency removal may precede public explanation when disclosure
would increase risk.

## Continuity and quorum

While only one maintainer exists, no release may claim independent maintainer
review. If that maintainer is unavailable or loses access, publication stops;
contributors must not reconstruct authority from repository secrets or create
an unofficial release under the project name.

After a second trusted maintainer is added, normative changes, release-workflow
changes, security-sensitive changes, and official releases require one
non-author maintainer approval. Candidate-standard advancement additionally
requires the independent implementer and governance gates in
`docs/governance.md`.
