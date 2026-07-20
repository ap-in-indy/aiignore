import { describe, expect, it } from 'vitest';
import { normalizeSbom } from '../scripts/normalize-sbom.mjs';

describe('release SBOM normalization', () => {
  it('removes npm run-specific identity and time while preserving deterministic content', () => {
    const first = fixture('urn:uuid:11111111-1111-4111-8111-111111111111', '2026-07-16T00:00:00Z');
    const second = fixture('urn:uuid:22222222-2222-4222-8222-222222222222', '2026-07-17T00:00:00Z');
    const identity = { name: '@apinindy/aiignore', version: '0.1.0-alpha.1' };
    const normalized = normalizeSbom(first, identity);
    expect(normalized).toBe(normalizeSbom(second, identity));
    expect(normalized).not.toContain('serialNumber');
    expect(normalized).not.toContain('timestamp');
    expect(normalized).toContain('"name": "@apinindy/aiignore"');
    expect(normalized).toContain('"version": "0.1.0-alpha.1"');
  });

  it('rejects documents that are not npm CycloneDX SBOMs', () => {
    expect(() => normalizeSbom({ bomFormat: 'SPDX' })).toThrow('supported CycloneDX');
    const inconsistent = fixture(
      'urn:uuid:11111111-1111-4111-8111-111111111111',
      '2026-07-16T00:00:00Z'
    );
    inconsistent.metadata.component['bom-ref'] = 'other-package@1.0.0';
    expect(() =>
      normalizeSbom(inconsistent, { name: '@apinindy/aiignore', version: '0.1.0-alpha.1' })
    ).toThrow('root references');
  });
});

function fixture(serialNumber: string, timestamp: string) {
  return {
    specVersion: '1.5',
    bomFormat: 'CycloneDX',
    serialNumber,
    metadata: {
      timestamp,
      component: {
        'bom-ref': '@apinindy/aiignore@0.1.0-alpha.1',
        purl: 'pkg:npm/%40apinindy/aiignore@0.1.0-alpha.1',
        version: '0.1.0-alpha.1',
        name: '@apinindy/aiignore',
        type: 'library'
      }
    },
    components: [{ version: '1.0.0', name: 'fixture', type: 'library' }],
    dependencies: [{ ref: '@apinindy/aiignore@0.1.0-alpha.1', dependsOn: ['fixture@1.0.0'] }]
  };
}
