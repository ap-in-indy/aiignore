# Fuzz targets

`fuzz.mjs` performs deterministic mutation-based robustness testing at the two
untrusted-input boundaries that the reference implementation exposes:

- policy bytes, replaying every portable parser vector exactly and mutating
  bounded vector, example, and profile seeds;
- file, environment, network, and string decision candidates.

The checked-in dictionary contains syntax and adversarial tokens. The ordinary
`verify` gate runs a short campaign so the target cannot silently bit-rot. The
scheduled `Extended fuzzing` workflow runs a larger campaign. A failure prints
only the seed, target, and iteration—not the generated input—and gives an exact
reproduction command.

This is deterministic robustness fuzzing, not a claim of exhaustive input
coverage, coverage-guided fuzzing, or independent security review. Any reduced
crasher must be added to the normative vectors or an appropriate regression
test before the defect is considered fixed.
