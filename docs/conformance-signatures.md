# Signing and verifying conformance reports

Conformance signatures let an organization prove that a particular signer
approved the exact bytes of an implementation or harness report. They do not certify that the
report is complete or correct.

## Trust model

Draft 0.1 uses Ed25519 and a small detached JSON envelope. Verification always
requires two values obtained through a separate trusted channel:

- the expected signer identity; and
- the SHA-256 fingerprint of the signer's Ed25519 public key in SPKI DER form.

Do not copy these trust pins from the report or its envelope. Publish them in a
reviewed administrator configuration, signed release, managed trust store, or
another authenticated channel. The envelope's embedded public key exists for
offline verification, not trust-on-first-use.

## Create a signing key

For a local test key:

```sh
openssl genpkey -algorithm Ed25519 -out conformance-signing-private.pem
chmod 600 conformance-signing-private.pem
```

Production signing keys should live in a protected signing service, hardware
device, or tightly controlled CI environment. The reference CLI accepts a
PKCS#8 PEM key file but never writes or prints its contents.

## Sign a provisional report

The input report must:

- have `status: provisional`;
- record a clean source state (`sourceTreeDirty: false` at the harness-report
  root or inside `implementation` for an implementation report); and
- include at least one content-addressed `evidence` entry.

Signing creates a new verified report and detached envelope without modifying
the input or overwriting an existing output:

```sh
aiignore sign-report provisional.json \
  --key conformance-signing-private.pem \
  --identity https://security.example/aiignore/conformance-signer \
  --issuer https://security.example/ \
  --envelope-uri https://evidence.example/report.signature.json \
  --report-out verified.json \
  --envelope-out verified.signature.json
```

The command prints the exact report SHA-256 and public-key SHA-256. Publish the
public-key fingerprint through the organization's trusted configuration or
release process, separately from the report and envelope.

## Verify with pinned trust

```sh
aiignore verify-report verified.json verified.signature.json \
  --identity https://security.example/aiignore/conformance-signer \
  --issuer https://security.example/ \
  --key-sha256 REVIEWED_PUBLIC_KEY_SHA256
```

Verification fails closed on malformed UTF-8 or JSON, schema drift, report-byte
changes, signature changes, non-Ed25519 keys, and any identity, issuer, or key
fingerprint mismatch.

For an implementation report, signature verification must be paired with
bundle verification against independently pinned manifest and vector bytes:

```sh
aiignore verify-implementation-report verified.json \
  --manifest conformance/manifest-v0.1.json
```

The signature authenticates who approved the report bytes; the bundle check
establishes that those bytes account for every parser/decision suite selected
by that manifest. Neither operation establishes live harness enforcement.

The envelope payload type selects the exact report schema and a distinct
domain-separation string. Changing an implementation report into a harness
payload type, or vice versa, invalidates schema and signature verification.

Key rotation requires a new out-of-band fingerprint and new signatures. Keep
old public keys available for historical verification, publish revocation and
compromise dates, and withdraw reports whose signing key or test evidence can
no longer be trusted.
