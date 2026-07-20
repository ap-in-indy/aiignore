# Fuzzing and robustness testing

The structured policy and every decision candidate are untrusted input. The
reference implementation therefore keeps deterministic mutation targets in the
repository and runs them continuously rather than treating fuzzing as a
one-time review exercise.

## Targets and invariants

`test/fuzz/fuzz.mjs` exercises two boundaries:

1. **Policy parser.** Every portable parser vector is replayed exactly;
   mutations use bounded vector entries, the complete example, and the
   recommended profile. Arbitrary invalid bytes
   may produce a documented `PolicyError`; they must not produce an unexpected
   exception. A successfully parsed policy must retain the exact input digest,
   be recursively immutable, parse identically a second time, construct an
   engine, and return deterministic decisions.
2. **Decision engine.** Generated Unicode, control, separator, URL, glob,
   prototype-property, and malformed candidates exercise every file operation,
   every string scope, environment filtering, and both case modes. Repeated
   calls must produce identical decisions or identical stable error codes.
   Decisions must bind to the policy digest and preserve the public result
   shape. Filtered environment records must retain null prototypes.

Inputs are capped so a pull request cannot turn this gate into uncontrolled
resource consumption. Normative boundary-size and cumulative-work behavior is
covered separately by the portable limit vectors.

## Running and reproducing

After `npm run build`:

```sh
npm run fuzz:smoke
npm run fuzz:extended -- --seed 0x12345678
npm run fuzz:smoke -- --seed 0x12345678 --iterations 417 --target parser
```

The normal `npm run verify` path executes 2,000 mutations per selected target.
The weekly workflow executes 25,000 per target and rotates its seed using the
workflow run number. Manual runs may supply a seed. Every campaign is exactly
reproducible from its seed and iteration count.

Before mutation, the target replays every exact parser vector and a
decision prelude covering all resource families, file operations, string
scopes, both case modes, and prototype-property environment filtering. This
makes surface coverage deterministic even when a particular random seed would
not select every branch.

Failure output deliberately excludes generated input. This prevents a future
real-world regression corpus from being echoed into public CI logs. Reduce a
failure locally, confirm it contains no private material, and add it to the
parser vectors, decision vectors, or a focused regression test before closing
the defect. Security-relevant failures follow `SECURITY.md` rather than a
public issue.

## Corpus and limitations

The committed parser vectors are the seed corpus and
`test/fuzz/aiignore.dict` supplies grammar and adversarial tokens. New parser or
canonicalization regressions must extend this corpus.

This campaign is deterministic mutation-based robustness testing. It is not a
claim of exhaustive state-space coverage, sanitizer instrumentation,
coverage-guided fuzzing, or independent security review. After the repository
is public and has an established user base, maintainers should evaluate a
JavaScript coverage-guided target and OSS-Fuzz or ClusterFuzzLite integration.
