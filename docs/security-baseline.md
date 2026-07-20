# OpenSSF OSPS Baseline control assessment

This is a maintainer self-assessment against [OpenSSF OSPS Baseline
2026.02.19](https://baseline.openssf.org/versions/2026-02-19.html), recorded as
**2026.02.19** for machine validation. It is not an OpenSSF badge, certification, third-party audit,
or claim of formal conformance. “Prepared” means repository code or
documentation exists but the release- or hosting-dependent control has not yet
been exercised. “Unverified” means the required external setting is not proven
by repository evidence.

The project does **not** currently satisfy Level 1 as a deployed project: the
authoritative repository is private, primary-branch protections are absent,
and maintainer-account MFA is not independently evidenced. Level 2 is designed
for projects with at least two maintainers; aiignore currently has one. Level 3
is assessed voluntarily to expose future gaps.

## Level 1 controls

| Control | Status | Evidence or gap |
| --- | --- | --- |
| OSPS-AC-01.01 MFA for sensitive resources | Unverified | Required by `docs/credential-management.md`; GitHub/npm account settings are owner-controlled and not proven here. |
| OSPS-AC-02.01 least-privilege collaborator assignment | Prepared | `MAINTAINERS.md` defines review before escalation; no repository collaborator inventory is publicly verifiable yet. |
| OSPS-AC-03.01 prevent direct primary-branch commits | Not met | A no-bypass desired ruleset and read-only hosting auditor exist, but no active `main` ruleset exists while private. |
| OSPS-AC-03.02 protect primary-branch deletion | Not met | Desired state blocks deletion and force-push and is machine-audited, but is not active while private. |
| OSPS-BR-01.01 validate untrusted pipeline metadata | Implemented | Workflows do not interpolate PR metadata into shells; release input is constrained to a strict prerelease-tag grammar and exact dispatch ref before CLI use. |
| OSPS-BR-01.03 isolate untrusted code from privileged assets | Implemented | Pull-request jobs have read-only contents and no secrets; publication is manual, tag-bound, and uses a protected environment/OIDC design. |
| OSPS-BR-03.01 encrypt official project channels | Prepared | All declared project/distribution URLs use HTTPS; public endpoints are not live yet. |
| OSPS-BR-03.02 cryptographically authenticate distribution | Prepared | npm integrity/provenance, signed tags, SHA-256 assets, attestations, and exact Pages verification exist in the release workflow but no release exists. |
| OSPS-BR-07.01 prevent unencrypted secrets in VCS | Implemented | Checksum-pinned, suppression-resistant Gitleaks scans every reachable revision on PRs, schedules, and releases. |
| OSPS-DO-01.01 basic user guide | Prepared | `README.md`, examples, recommended profile, CLI help, and adapter guides cover released functionality; no package release exists. |
| OSPS-DO-02.01 defect-reporting guide | Prepared | Structured bug, RFC, and conformance issue forms plus `CONTRIBUTING.md`; issue tracker is private until launch. |
| OSPS-GV-02.01 public change/usage discussion | Prepared | Issues, Discussions, RFC process, and support policy are configured but not public. |
| OSPS-GV-03.01 contribution process | Implemented | `CONTRIBUTING.md`, pull-request template, RFC process, DCO, and automated sign-off validation. |
| OSPS-LE-02.01 open-source source license | Implemented | OSI-approved MIT License. |
| OSPS-LE-02.02 open-source release license | Prepared | MIT `LICENSE` is required in the npm payload; no official release exists. |
| OSPS-LE-03.01 source license in well-known location | Implemented | Root `LICENSE` contains the complete MIT license terms. |
| OSPS-LE-03.02 release license distributed | Prepared | Package validation requires `LICENSE`; no official release exists. |
| OSPS-QA-01.01 source publicly readable at a static URL | Not met | Repository visibility is private. |
| OSPS-QA-01.02 public attributable change history | Not met | Git history is attributable but not publicly readable while private. |
| OSPS-QA-02.01 direct dependency list | Implemented | `package.json` and authenticated lock graph in `package-lock.json`. |
| OSPS-QA-04.01 list project repositories | Not applicable | The project currently has one authoritative repository, recorded in `security-insights.yml`. |
| OSPS-QA-05.01 no generated executable artifacts in VCS | Implemented | Builds live in ignored `dist/`; package checks reject development/generated repository paths. |
| OSPS-QA-05.02 no unreviewable binary artifacts in VCS | Implemented | Required source/specification/evidence is reviewable text; binary extensions are inspected by repository policy and Scorecard after public launch. |
| OSPS-VM-02.01 security contacts | Implemented | `SECURITY.md` and `security-insights.yml` name the private advisory channel and email contact. |

## Level 2 controls

| Control | Status | Evidence or gap |
| --- | --- | --- |
| OSPS-AC-04.01 least-privilege default CI permissions | Prepared | Every workflow declares explicit permissions; desired state requires read-only defaults and forbids workflow PR approval, but the public owner-side audit has not passed. |
| OSPS-BR-02.01 unique release versions | Prepared | `docs/versioning.md`, SemVer package identity, signed tag, and release workflow bind one immutable version. |
| OSPS-BR-04.01 functional/security change log | Prepared | `CHANGELOG.md` and exact tagged release notes are required and authenticated; no release exists. |
| OSPS-BR-05.01 standardized dependency tooling | Implemented | npm lockfile, `npm ci --ignore-scripts`, audit, signature verification, license checks, and Dependabot. |
| OSPS-BR-06.01 signed release or signed manifest | Prepared | Owner-only tag creation, exact verified tagger identity, restricted tag-only deployment, and attestations covering tarball, SBOM, and checksums; not yet exercised publicly. The alpha has no independent human release approval. |
| OSPS-DO-06.01 dependency-selection/tracking guide | Implemented | `docs/dependency-management.md`. |
| OSPS-DO-07.01 build instructions | Implemented | README quick start, Node engine constraint, lockfile install, and build/verify commands. |
| OSPS-GV-01.01 sensitive-resource member list | Implemented | `MAINTAINERS.md` lists the sole current release/security authority and explicitly states the bus-factor limitation. |
| OSPS-GV-01.02 member roles/responsibilities | Implemented | `MAINTAINERS.md` defines editor, implementation, security, release, access-review, and continuity responsibilities. |
| OSPS-GV-03.02 acceptable-contribution guide | Implemented | `CONTRIBUTING.md`, RFC template, required tests/vectors, DCO, and security-data restrictions. |
| OSPS-LE-01.01 contributor authorization assertion | Prepared | Verbatim DCO 1.1, `git commit -s` requirement, and trusted-base PR workflow validating every commit against author name/email; enforcement awaits a required branch check. |
| OSPS-QA-03.01 primary-branch status checks pass | Not met | Checks exist and pass on the candidate, but no repository ruleset currently enforces them. |
| OSPS-QA-06.01 automated tests before acceptance | Prepared | Cross-platform CI runs the full gate on PRs; enforcement awaits public branch rules. |
| OSPS-SA-01.01 actions/actors design documentation | Prepared | `docs/architecture.md`, `docs/concept.md`, and enterprise control architecture; no release exists. |
| OSPS-SA-02.01 external-interface documentation | Prepared | `docs/architecture.md`, README CLI/API surface, package exports, and adapter guides; no release exists. |
| OSPS-SA-03.01 security assessment | Prepared | Threat model, incident research, adversarial results, and this self-assessment; no independent assessment or release exists. |
| OSPS-VM-01.01 coordinated disclosure with timeframe | Implemented | `SECURITY.md` defines private intake, five-business-day acknowledgement target, triage, coordination, and publication. |
| OSPS-VM-03.01 private vulnerability reporting | Implemented | Direct security email works while private; GitHub private vulnerability reporting activates at public launch. |
| OSPS-VM-04.01 publish discovered vulnerability data | Prepared | Security advisories, release notes, changelog, and withdrawal policy are defined; no discovered published vulnerability exists. |

The project has only one maintainer and therefore does not claim Level 2 project
maturity even where individual controls are implemented.

## Level 3 controls

| Control | Status | Evidence or gap |
| --- | --- | --- |
| OSPS-AC-04.02 minimum explicit CI privileges | Implemented | Workflow validator requires explicit permissions, forbids dangerous triggers, isolates dependency/build execution from the protected OIDC/write job, and mutation-tests critical release controls. |
| OSPS-BR-01.04 validate trusted collaborator input | Implemented | Manual release tag has a strict grammar, exact ref binding, signed-tag verification, version agreement, and `main` ancestry check. |
| OSPS-BR-02.02 associate assets with release identifier | Prepared | Versioned tarball/SBOM names, exact asset set, authenticated title/notes, and immutable tag; no release exists. |
| OSPS-BR-07.02 project secret/credential policy | Implemented | `docs/credential-management.md` covers storage, access, OIDC, purpose separation, rotation, revocation, and compromise response. |
| OSPS-DO-03.01 release integrity/authenticity verification | Prepared | `docs/maintainer-release-runbook.md` includes checksum, npm SRI, attestation, and anonymous verification commands. |
| OSPS-DO-03.02 release-author identity verification | Prepared | Verified annotated tag requirement and signing-identity publication gate; the real key is not configured. |
| OSPS-DO-04.01 support scope/duration | Prepared | `SUPPORT.md`, `SECURITY.md`, and `docs/versioning.md` define latest-alpha-only support; no release exists. |
| OSPS-DO-05.01 end-of-support statement | Prepared | New prerelease ends routine support for the prior alpha; stable support is explicitly deferred until 1.0. |
| OSPS-GV-04.01 review before collaborator escalation | Implemented | `MAINTAINERS.md` defines documented need, least privilege, review, access inventory, and removal criteria. |
| OSPS-QA-02.02 SBOM with compiled release assets | Prepared | Deterministic CycloneDX SBOM is a required attested release asset; no release exists. |
| OSPS-QA-04.02 equivalent subproject security | Not applicable | No subproject repository exists. |
| OSPS-QA-06.02 document when/how tests run | Implemented | `docs/test-coverage.md`, `docs/fuzzing.md`, workflows, and `npm run verify`. |
| OSPS-QA-06.03 major changes update tests | Implemented | `CONTRIBUTING.md`, RFC lifecycle, and coverage contract require tests and portable vectors for normative/major changes. |
| OSPS-QA-07.01 non-author human approval | Not met | A sole maintainer cannot provide independent approval. The public-alpha rules deliberately require automated gates but zero human approvals; this control remains unmet until a second trusted maintainer exists. |
| OSPS-SA-03.02 threat model and attack-surface analysis | Implemented | `docs/concept.md`, `docs/architecture.md`, incident research, adapter gaps, and adversarial result register. Independent review remains missing. |
| OSPS-VM-04.02 VEX for non-affecting component vulnerabilities | Prepared | Dependency policy requires a recorded non-exploitability rationale; release VEX generation is not yet implemented because no current production finding requires one. |
| OSPS-VM-05.01 SCA remediation threshold | Implemented | Any production vulnerability at low severity or unapproved/unknown production license blocks release unless a documented non-exploitability decision exists. |
| OSPS-VM-05.02 address SCA before release | Implemented | CI/release run production audit, registry-signature, dependency-review, and license gates. Public enforcement remains owner-controlled. |
| OSPS-VM-05.03 automatically block dependency violations | Prepared | npm audit/license checks run now; dependency review activates when public and rulesets must make it required. Malicious-package review still includes human provenance review. |
| OSPS-VM-06.01 SAST remediation threshold | Implemented policy | High/critical findings and exploitable lower-severity findings block release; suppressions require a public rationale after remediation risk permits. |
| OSPS-VM-06.02 automatically block SAST violations | Not met | CodeQL workflow exists but skips while private and no code-scanning merge rule is active. |

## Other material limitations

- No independent parser or independent security assessment has been published.
- No neutral multi-organization governance, standards-essential patent policy,
  or conformance trademark program exists.
- Live harness sandbox evidence remains limited and explicitly scoped.
- Repository settings, account MFA, signing-key custody, npm ownership, and
  public URLs require external activation and anonymous verification.

These gaps do not prevent a clearly labeled public alpha for interoperability
testing. They do prevent Level 1 deployment claims today and prevent
candidate-standard, certification, or universal enterprise-security claims.

Review this assessment for every release and whenever hosting, maintainers,
interfaces, workflows, security tooling, or support scope changes.
