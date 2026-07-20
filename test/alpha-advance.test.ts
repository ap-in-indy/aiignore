import { describe, expect, it } from 'vitest';
import { assertAlphaAdvance } from '../scripts/validate-alpha-advance.mjs';

describe('npm alpha channel monotonicity', () => {
  it('accepts strictly newer alpha identifiers and base versions', () => {
    expect(() => assertAlphaAdvance('0.1.0-alpha.1', '0.1.0-alpha.2')).not.toThrow();
    expect(() => assertAlphaAdvance('0.1.9-alpha.99', '0.2.0-alpha.1')).not.toThrow();
    expect(() => assertAlphaAdvance('9.9.9-alpha.9', '10.0.0-alpha.1')).not.toThrow();
  });

  it('rejects equal or backward publication', () => {
    expect(() => assertAlphaAdvance('0.1.0-alpha.2', '0.1.0-alpha.2')).toThrow(
      'does not advance'
    );
    expect(() => assertAlphaAdvance('0.2.0-alpha.1', '0.1.99-alpha.99')).toThrow(
      'move the alpha channel backward'
    );
  });

  it('rejects malformed or non-alpha channel values', () => {
    expect(() => assertAlphaAdvance('0.1.0', '0.2.0-alpha.1')).toThrow(
      'not an alpha.N Semantic Version'
    );
    expect(() => assertAlphaAdvance('0.1.0-alpha.1', '0.2.0-beta.1')).toThrow(
      'not an alpha.N Semantic Version'
    );
  });
});
