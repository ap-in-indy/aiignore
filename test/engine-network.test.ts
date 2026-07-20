import { describe, expect, it } from 'vitest';
import { PolicyEngine } from '../src/engine.js';
import { PolicyError } from '../src/errors.js';
import { policy } from './helpers.js';

const engine = new PolicyEngine(
  policy(`aiignore: "0.1"
defaults: {network: deny}
rules:
  network:
    - id: docs
      effect: allow
      urls: ["https://**.example.com/docs/**"]
    - id: upload
      effect: deny
      priority: 10
      urls: ["https://docs.example.com/docs/upload/**"]
    - id: subdomain-only
      effect: allow
      urls: ["https://*.packages.test/**"]
    - id: mirrors
      effect: allow
      urls: ["https://mirror.test/**"]
      except: ["https://mirror.test/private/**"]
`)
);

describe('network decisions', () => {
  it('matches apex-and-subdomain hosts and canonical default ports', () => {
    expect(engine.decideNetwork('https://example.com/docs/start').effect).toBe('allow');
    expect(engine.decideNetwork('https://docs.example.com:443/docs/start').effect).toBe('allow');
  });

  it('does not let wildcard suffixes match attacker-controlled lookalikes', () => {
    expect(engine.decideNetwork('https://example.com.evil.test/docs/start').effect).toBe('deny');
  });

  it('distinguishes subdomains-only from apex-and-subdomains', () => {
    expect(engine.decideNetwork('https://one.packages.test/x').effect).toBe('allow');
    expect(engine.decideNetwork('https://packages.test/x').effect).toBe('deny');
  });

  it('applies path rules and priority', () => {
    expect(engine.decideNetwork('https://docs.example.com/docs/upload/key').ruleId).toBe('upload');
  });

  it('applies a whole-rule network exception', () => {
    expect(engine.decideNetwork('https://mirror.test/public/file').effect).toBe('allow');
    expect(engine.decideNetwork('https://mirror.test/private/file').effect).toBe('deny');
  });

  it('rejects userinfo, fragments, and unsupported schemes', () => {
    expect(() => engine.decideNetwork('https://user@example.com/docs')).toThrowError(PolicyError);
    expect(() => engine.decideNetwork('https://example.com/docs#fragment')).toThrowError(PolicyError);
    expect(() => engine.decideNetwork('file:///etc/passwd')).toThrowError(PolicyError);
    expect(() => engine.decideNetwork('https://example.com/docs%2fprivate')).toThrowError(
      PolicyError
    );
  });
});
