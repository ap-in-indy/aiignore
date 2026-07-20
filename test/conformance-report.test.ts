import { readdirSync, readFileSync } from 'node:fs';
import { Ajv2020 } from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';

describe('machine-readable conformance reports', () => {
  it('validates every committed report against the report schema', () => {
    const schema = JSON.parse(
      readFileSync(new URL('../schema/conformance-report.schema.json', import.meta.url), 'utf8')
    ) as object;
    const ajv = new Ajv2020({ allErrors: true, strict: true, validateFormats: false });
    const validate = ajv.compile(schema);
    const directory = new URL('../conformance/results/', import.meta.url);
    const files = readdirSync(directory).filter((file) => file.endsWith('.json'));
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const report = JSON.parse(readFileSync(new URL(file, directory), 'utf8')) as unknown;
      expect(validate(report), `${file}: ${JSON.stringify(validate.errors)}`).toBe(true);
    }
  });

  it('requires detached verification evidence for verified status', () => {
    const schema = JSON.parse(
      readFileSync(new URL('../schema/conformance-report.schema.json', import.meta.url), 'utf8')
    ) as object;
    const report = JSON.parse(
      readFileSync(
        new URL('../conformance/results/codex-0.144.5-macos-26.5.2.json', import.meta.url),
        'utf8'
      )
    ) as Record<string, unknown>;
    const activeReport = structuredClone(report);
    delete activeReport['withdrawalReason'];
    const validate = new Ajv2020({ allErrors: true, strict: true, validateFormats: false }).compile(
      schema
    );
    expect(validate({ ...activeReport, status: 'verified' })).toBe(false);
    expect(
      validate({
        ...activeReport,
        status: 'verified',
        sourceTreeDirty: true,
        verification: {
          method: 'aiignore-ed25519-v0.1',
          identity: 'maintainer@example.invalid',
          envelopeUri: 'https://example.invalid/report.sig.json',
          publicKeySha256: '0'.repeat(64)
        },
        evidence: [
          { type: 'signature', uri: 'https://example.invalid/report.sig', sha256: '0'.repeat(64) }
        ]
      })
    ).toBe(false);
    expect(
      validate({
        ...activeReport,
        status: 'verified',
        verification: {
          method: 'aiignore-ed25519-v0.1',
          identity: 'https://github.com/example/repository/.github/workflows/conformance.yml',
          issuer: 'https://token.actions.githubusercontent.com',
          envelopeUri: 'https://example.invalid/report.signature.json',
          publicKeySha256: '1'.repeat(64)
        },
        evidence: [
          {
            type: 'attestation',
            uri: 'https://example.invalid/report.sigstore.json',
            sha256: '0'.repeat(64)
          }
        ]
      })
    ).toBe(true);

    expect(validate({ ...activeReport, status: 'withdrawn' })).toBe(false);
    expect(
      validate({
        ...activeReport,
        status: 'withdrawn',
        withdrawalReason: 'Superseded after a testbed defect.'
      })
    ).toBe(true);
    expect(
      validate({
        ...activeReport,
        status: 'provisional',
        withdrawalReason: 'Must not appear on an active report.'
      })
    ).toBe(false);
  });
});
