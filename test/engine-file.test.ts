import { describe, expect, it } from 'vitest';
import { PolicyEngine } from '../src/engine.js';
import { PolicyError } from '../src/errors.js';
import { policy } from './helpers.js';

const engine = new PolicyEngine(
  policy(`aiignore: "0.1"
rules:
  files:
    - id: secrets
      effect: deny
      paths: ["**/.env*", "secrets/**"]
      except: ["**/.env.example"]
    - id: generated
      effect: read-only
      paths: ["generated/**"]
    - id: lower-priority
      effect: allow
      priority: -1
      paths: ["secrets/public.txt"]
    - id: higher-priority
      effect: allow
      priority: 50
      paths: ["secrets/releasable.txt"]
`)
);

describe('file decisions', () => {
  it('matches root and nested dotfiles', () => {
    expect(engine.decideFile('.env', 'read').effect).toBe('deny');
    expect(engine.decideFile('apps/api/.env.local', 'read').effect).toBe('deny');
  });

  it('applies local exceptions without creating an implicit allow rule', () => {
    const decision = engine.decideFile('apps/api/.env.example', 'read');
    expect(decision.effect).toBe('allow');
    expect(decision.ruleId).toBeNull();
  });

  it('uses priority before file order', () => {
    expect(engine.decideFile('secrets/public.txt', 'read').ruleId).toBe('secrets');
    expect(engine.decideFile('secrets/releasable.txt', 'read').ruleId).toBe('higher-priority');
  });

  it('implements read-only by operation', () => {
    expect(engine.decideFile('generated/client.ts', 'read').effect).toBe('allow');
    expect(engine.decideFile('generated/client.ts', 'write').effect).toBe('deny');
    expect(engine.decideFile('generated/client.ts', 'execute').effect).toBe('deny');
  });

  it('rejects lexical path escapes and NUL', () => {
    expect(() => engine.decideFile('../outside', 'read')).toThrowError(PolicyError);
    expect(() => engine.decideFile('bad\0path', 'read')).toThrowError(PolicyError);
  });

  it('rejects unknown operations instead of falling through to allow', () => {
    expect(() => engine.decideFile('secrets/key', 'reed' as never)).toThrow(/operation is not supported/u);
  });

  it('bounds candidate bytes and cumulative matcher work', () => {
    expect(() => engine.decideFile('A'.repeat(1024 * 1024 + 1), 'read')).toThrowError(
      PolicyError
    );
    const patterns = Array.from({ length: 17 }, (_, index) =>
      `B${String(index).padStart(2, '0')}`
    );
    const bounded = new PolicyEngine(
      policy(`aiignore: "0.1"\nrules:\n  files:\n    - {id: bounded, effect: deny, paths: [${patterns.join(', ')}]}\n`)
    );
    expect(() => bounded.decideFile('A'.repeat(1024 * 1024), 'read')).toThrow(
      /cumulative resource matcher work/u
    );
  });

  it('supports native case-insensitive filesystem aliases explicitly', () => {
    expect(engine.decideFile('SECRETS/key.txt', 'read', engine.policy.root, false).effect).toBe(
      'allow'
    );
    expect(engine.decideFile('SECRETS/key.txt', 'read', engine.policy.root, true).effect).toBe(
      'deny'
    );
  });
});
