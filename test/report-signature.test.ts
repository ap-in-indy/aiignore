import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  signConformanceReport,
  verifyConformanceReport,
  type ConformanceSignatureEnvelope
} from '../src/report-signature.js';

const identity = 'https://example.invalid/aiignore/conformance-signer';
const issuer = 'https://example.invalid/security';
const envelopeUri = 'https://example.invalid/reports/codex.signature.json';

describe('detached conformance report signatures', () => {
  it('signs exact report bytes and verifies against pinned identity, issuer, and key', () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const signed = signConformanceReport(
      provisionalReport(),
      privateKey.export({ type: 'pkcs8', format: 'pem' }),
      { identity, issuer, envelopeUri }
    );
    const report = JSON.parse(Buffer.from(signed.reportBytes).toString('utf8')) as Record<
      string,
      unknown
    >;
    expect(report).toMatchObject({
      status: 'verified',
      verification: {
        method: 'aiignore-ed25519-v0.1',
        identity,
        issuer,
        envelopeUri,
        publicKeySha256: signed.publicKeySha256
      }
    });
    expect(
      verifyConformanceReport(signed.reportBytes, signed.envelopeBytes, {
        expectedIdentity: identity,
        expectedIssuer: issuer,
        expectedPublicKeySha256: signed.publicKeySha256
      })
    ).toEqual({
      verified: true,
      reportSha256: signed.reportSha256,
      publicKeySha256: signed.publicKeySha256,
      identity,
      issuer,
      payloadType: 'application/vnd.aiignore.conformance-report+json;version=0.1'
    });
  });

  it('rejects report, signature, identity, issuer, and key substitution', () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const signed = signConformanceReport(
      provisionalReport(),
      privateKey.export({ type: 'pkcs8', format: 'pem' }),
      { identity, issuer, envelopeUri }
    );
    const trusted = {
      expectedIdentity: identity,
      expectedIssuer: issuer,
      expectedPublicKeySha256: signed.publicKeySha256
    };
    const tamperedReport = Buffer.from(
      Buffer.from(signed.reportBytes).toString('utf8').replace('0.144.5', '0.144.6')
    );
    expect(() =>
      verifyConformanceReport(tamperedReport, signed.envelopeBytes, trusted)
    ).toThrow(/signed digest/u);

    const envelope = JSON.parse(
      Buffer.from(signed.envelopeBytes).toString('utf8')
    ) as ConformanceSignatureEnvelope;
    envelope.signatureBase64 = `${envelope.signatureBase64[0] === 'A' ? 'B' : 'A'}${envelope.signatureBase64.slice(1)}`;
    expect(() =>
      verifyConformanceReport(
        signed.reportBytes,
        Buffer.from(JSON.stringify(envelope)),
        trusted
      )
    ).toThrow(/signature is invalid/u);

    expect(() =>
      verifyConformanceReport(signed.reportBytes, signed.envelopeBytes, {
        ...trusted,
        expectedIdentity: 'https://attacker.invalid/signer'
      })
    ).toThrow(/identity is not trusted/u);
    expect(() =>
      verifyConformanceReport(signed.reportBytes, signed.envelopeBytes, {
        ...trusted,
        expectedIssuer: 'https://attacker.invalid/issuer'
      })
    ).toThrow(/issuer is not trusted/u);
    expect(() =>
      verifyConformanceReport(signed.reportBytes, signed.envelopeBytes, {
        ...trusted,
        expectedPublicKeySha256: '0'.repeat(64)
      })
    ).toThrow(/public key is not trusted/u);
  });

  it('refuses to promote dirty, evidence-free, or already final reports', () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const key = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const report = JSON.parse(Buffer.from(provisionalReport()).toString('utf8')) as Record<
      string,
      unknown
    >;
    expect(() =>
      signConformanceReport(Buffer.from(JSON.stringify({ ...report, sourceTreeDirty: true })), key, {
        identity,
        envelopeUri
      })
    ).toThrow(/dirty source tree/u);
    const withoutEvidence = { ...report };
    delete withoutEvidence['evidence'];
    expect(() =>
      signConformanceReport(Buffer.from(JSON.stringify(withoutEvidence)), key, {
        identity,
        envelopeUri
      })
    ).toThrow(/requires content-addressed evidence/u);
    expect(() =>
      signConformanceReport(
        Buffer.from(
          JSON.stringify({
            ...report,
            status: 'withdrawn',
            withdrawalReason: 'Superseded by a later report.'
          })
        ),
        key,
        { identity, envelopeUri }
      )
    ).toThrow(/only a provisional report/u);

    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({
      type: 'pkcs8',
      format: 'pem'
    });
    expect(() =>
      signConformanceReport(provisionalReport(), rsa, { identity, envelopeUri })
    ).toThrow(/must use Ed25519/u);
    expect(() =>
      signConformanceReport(provisionalReport(), Buffer.from('not a key'), {
        identity,
        envelopeUri
      })
    ).toThrow(/valid PKCS#8 PEM/u);
    expect(() =>
      signConformanceReport(provisionalReport(), key, {
        identity,
        envelopeUri: 'http://example.invalid/signature.json'
      })
    ).toThrow(/bounded HTTPS URI/u);
    expect(() =>
      signConformanceReport(provisionalReport(), key, {
        identity: 'bad\nidentity',
        envelopeUri
      })
    ).toThrow(/identity is invalid/u);
  });

  it('fails closed on malformed report and envelope containers', () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const key = privateKey.export({ type: 'pkcs8', format: 'pem' });
    expect(() =>
      signConformanceReport(Buffer.from('{}'), key, { identity, envelopeUri })
    ).toThrow(/conformance report:/u);
    expect(() =>
      signConformanceReport(Buffer.from([0xff]), key, { identity, envelopeUri })
    ).toThrow(/report is not valid UTF-8/u);
    expect(() =>
      signConformanceReport(Buffer.from('{'), key, { identity, envelopeUri })
    ).toThrow(/report is not valid JSON/u);
    expect(() =>
      signConformanceReport(Buffer.alloc(4 * 1024 * 1024 + 1), key, {
        identity,
        envelopeUri
      })
    ).toThrow(/report exceeds/u);

    const signed = signConformanceReport(provisionalReport(), key, { identity, envelopeUri });
    const trusted = {
      expectedIdentity: identity,
      expectedPublicKeySha256: signed.publicKeySha256
    };
    expect(() =>
      verifyConformanceReport(provisionalReport(), signed.envelopeBytes, trusted)
    ).toThrow(/status must be verified/u);
    expect(() =>
      verifyConformanceReport(signed.reportBytes, Buffer.from('{}'), trusted)
    ).toThrow(/signature envelope:/u);
    expect(() =>
      verifyConformanceReport(signed.reportBytes, Buffer.from([0xff]), trusted)
    ).toThrow(/envelope is not valid UTF-8/u);
    expect(() =>
      verifyConformanceReport(signed.reportBytes, Buffer.from('{'), trusted)
    ).toThrow(/envelope is not valid JSON/u);
    expect(() =>
      verifyConformanceReport(signed.reportBytes, Buffer.alloc(64 * 1024 + 1), trusted)
    ).toThrow(/envelope exceeds/u);
    expect(() =>
      verifyConformanceReport(signed.reportBytes, signed.envelopeBytes, {
        ...trusted,
        expectedPublicKeySha256: 'invalid'
      })
    ).toThrow(/expected public-key SHA-256/u);
  });

  it('rejects invalid or non-Ed25519 embedded public keys', () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const signed = signConformanceReport(provisionalReport(), privateKey.export({
      type: 'pkcs8',
      format: 'pem'
    }), { identity, envelopeUri });
    const trusted = {
      expectedIdentity: identity,
      expectedPublicKeySha256: signed.publicKeySha256
    };
    const invalid = JSON.parse(
      Buffer.from(signed.envelopeBytes).toString('utf8')
    ) as ConformanceSignatureEnvelope;
    invalid.publicKey.value =
      '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n';
    expect(() =>
      verifyConformanceReport(signed.reportBytes, Buffer.from(JSON.stringify(invalid)), trusted)
    ).toThrow(/public key is invalid/u);

    const rsaPublic = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({
      type: 'spki',
      format: 'pem'
    }).toString();
    invalid.publicKey.value = rsaPublic;
    expect(() =>
      verifyConformanceReport(signed.reportBytes, Buffer.from(JSON.stringify(invalid)), trusted)
    ).toThrow(/must use Ed25519/u);
  });
});

function provisionalReport(): Uint8Array {
  const report = JSON.parse(
    readFileSync(
      new URL('../conformance/results/codex-0.144.5-macos-26.5.2.json', import.meta.url),
      'utf8'
    )
  ) as Record<string, unknown>;
  report['evidence'] = [
    {
      type: 'artifact',
      uri: 'https://example.invalid/evidence/codex-run.log',
      sha256: '1'.repeat(64)
    }
  ];
  return Buffer.from(`${JSON.stringify(report, null, 2)}\n`);
}
