import { mkdtempSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { PolicyError } from '../src/errors.js';
import { PolicyEngine } from '../src/engine.js';
import { loadPinnedPolicy, loadPolicy, MAX_POLICY_BYTES, parsePolicy } from '../src/parser.js';
import { BASE } from './helpers.js';

describe('policy parser', () => {
  it('parses the restricted YAML data model and returns a digest', () => {
    const source = path.join(path.parse(process.cwd()).root, 'repo', '.aiignore.yaml');
    const loaded = parsePolicy(`${BASE}defaults:\n  network: deny\n`, source);
    expect(loaded.document.defaults?.network).toBe('deny');
    expect(loaded.digest).toMatch(/^[a-f0-9]{64}$/u);
    expect(loaded.root).toBe(path.dirname(source));
  });

  it('deeply freezes policy semantics so they cannot diverge from the byte digest', () => {
    const loaded = parsePolicy(
      `${BASE}defaults:\n  files: deny\nrules:\n  files:\n    - {id: public, effect: allow, paths: [public/**]}\n`
    );
    expect(Object.isFrozen(loaded.document)).toBe(true);
    expect(Object.isFrozen(loaded)).toBe(true);
    expect(Object.isFrozen(loaded.document.defaults)).toBe(true);
    expect(Object.isFrozen(loaded.document.rules?.files)).toBe(true);
    expect(Object.isFrozen(loaded.document.rules?.files?.[0])).toBe(true);
    const originalDigest = loaded.digest;
    expect(() => {
      (loaded.document.defaults as { files: string }).files = 'allow';
    }).toThrow(TypeError);
    expect(() => {
      (loaded as { digest: string }).digest = '0'.repeat(64);
    }).toThrow(TypeError);
    expect(() => {
      (loaded as { root: string }).root = '/forged-root';
    }).toThrow(TypeError);
    const decision = new PolicyEngine(loaded).decideFile('private/key', 'read');
    expect(decision.effect).toBe('deny');
    expect(decision.policyDigest).toBe(originalDigest);
  });

  it('snapshots policy wrapper metadata when constructing an engine', () => {
    const loaded = parsePolicy(`${BASE}defaults:\n  files: deny\n`);
    const mutable = { ...loaded };
    const engine = new PolicyEngine(mutable);
    mutable.digest = '0'.repeat(64);
    mutable.root = '/forged-root';
    expect(engine.policy.digest).toBe(loaded.digest);
    expect(engine.policy.root).toBe(loaded.root);
    expect(engine.decideFile('private/key', 'read').policyDigest).toBe(loaded.digest);
  });

  it('rejects duplicate mapping keys', () => {
    expect(() => parsePolicy(`${BASE}aiignore: "0.1"\n`)).toThrow(/Map keys must be unique/u);
  });

  it('rejects multiple YAML documents', () => {
    expect(() => parsePolicy(`${BASE}---\naiignore: "0.1"\n`)).toThrow(/multiple documents/u);
  });

  it('rejects aliases and anchors', () => {
    const yaml = `${BASE}metadata: &meta\n  name: example\nrules: *meta\n`;
    expect(() => parsePolicy(yaml)).toThrowError(PolicyError);
    expect(() => parsePolicy(yaml)).toThrow(/anchors|aliases/u);
  });

  it('rejects explicit tags and merge keys', () => {
    expect(() => parsePolicy(`${BASE}metadata: !!map {name: example}\n`)).toThrow(/explicit tags/u);
    expect(() =>
      parsePolicy(`${BASE}metadata:\n  <<: {name: example}\n`)
    ).toThrow(/merge keys/u);
  });

  it('rejects unknown properties and duplicate rule ids', () => {
    expect(() => parsePolicy(`${BASE}surprise: true\n`)).toThrow(/additional properties/u);
    const yaml = `${BASE}rules:\n  files:\n    - {id: same, effect: deny, paths: [a]}\n  network:\n    - {id: same, effect: deny, urls: ["https://example.com/**"]}\n`;
    expect(() => parsePolicy(yaml)).toThrow(/duplicate rule id/u);
  });

  it('rejects non-portable glob and regex features', () => {
    expect(() =>
      parsePolicy(`${BASE}rules:\n  files:\n    - {id: bad, effect: deny, paths: ["{a,b}"]}\n`)
    ).toThrow(/brace expansion/u);
    expect(() =>
      parsePolicy(`${BASE}rules:\n  strings:\n    - id: bad\n      effect: deny\n      patterns: [{type: regex, value: "(a)\\\\1"}]\n`)
    ).toThrow(/invalid RE2/u);
  });

  it('does not echo sensitive regex source in validation errors', () => {
    const canary = 'AIIGNORE-PRIVATE-REGEX-CANARY';
    let message = '';
    try {
      parsePolicy(`${BASE}rules:\n  strings:\n    - id: bad\n      effect: deny\n      patterns: [{type: regex, value: "(${canary}"}]\n`);
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    expect(message).toMatch(/invalid RE2/u);
    expect(message).not.toContain(canary);
  });

  it('rejects documents above the size limit', () => {
    expect(() => parsePolicy(Buffer.alloc(MAX_POLICY_BYTES + 1, 0x20))).toThrow(/exceeds/u);
  });

  it('rejects invalid UTF-8', () => {
    expect(() => parsePolicy(Buffer.from([0xc3, 0x28]))).toThrow(/UTF-8/u);
    expect(() => parsePolicy(new Uint8Array([0xc3, 0x28]))).toThrow(/UTF-8/u);
  });

  it('enforces inclusive scalar schema boundaries', () => {
    const maximumId = `a${'b'.repeat(63)}`;
    expect(() =>
      parsePolicy(`${BASE}metadata:\n  name: ${'n'.repeat(128)}\n  description: ${'d'.repeat(2048)}\nrules:\n  files:\n    - {id: ${maximumId}, effect: deny, priority: -1000, paths: [x]}\n    - {id: upper, effect: audit, priority: 1000, paths: [y]}\n  strings:\n    - id: replacement\n      effect: redact\n      patterns: [{type: literal, value: ${'p'.repeat(4096)}}]\n      replacement: ${'r'.repeat(1024)}\n`)
    ).not.toThrow();
    expect(() =>
      parsePolicy(`${BASE}rules:\n  files:\n    - {id: a${'b'.repeat(64)}, effect: deny, paths: [x]}\n`)
    ).toThrowError(PolicyError);
    expect(() => parsePolicy(`${BASE}metadata:\n  name: ${'n'.repeat(129)}\n`)).toThrowError(
      PolicyError
    );
    expect(() =>
      parsePolicy(`${BASE}rules:\n  strings:\n    - id: too-long\n      effect: redact\n      patterns: [{type: literal, value: x}]\n      replacement: ${'r'.repeat(1025)}\n`)
    ).toThrowError(PolicyError);
  });

  it('loads regular files and rejects non-files', () => {
    const directory = mkdtempSync(path.join(tmpdir(), 'aiignore-parser-'));
    const file = path.join(directory, '.aiignore.yaml');
    writeFileSync(file, BASE);
    expect(loadPolicy(file).source).toBe(file);
    expect(() => loadPolicy(directory)).toThrow(/not a regular file/u);
    const oversized = path.join(directory, 'oversized.aiignore.yaml');
    writeFileSync(oversized, Buffer.alloc(MAX_POLICY_BYTES + 1, 0x20));
    expect(() => loadPolicy(oversized)).toThrowError(
      expect.objectContaining({ code: 'policy_too_large' })
    );
    if (process.platform !== 'win32') {
      const link = path.join(directory, 'linked.aiignore.yaml');
      symlinkSync(file, link);
      expect(() => loadPolicy(link)).toThrowError(
        expect.objectContaining({ code: 'not_a_file' })
      );
    }
  });

  it('treats an explicitly supplied empty digest as a failed pin', () => {
    const directory = mkdtempSync(path.join(tmpdir(), 'aiignore-parser-digest-'));
    const file = path.join(directory, '.aiignore.yaml');
    writeFileSync(file, BASE);
    expect(() => loadPinnedPolicy(file, '')).toThrowError(
      expect.objectContaining({ code: 'policy_digest_mismatch' })
    );
  });

  it('returns stable errors for missing policies and legacy compatibility files', () => {
    const directory = mkdtempSync(path.join(tmpdir(), 'aiignore-parser-missing-'));
    const structured = path.join(directory, '.aiignore.yaml');
    expect(() => loadPolicy(structured)).toThrowError(
      expect.objectContaining({ code: 'policy_not_found' })
    );

    writeFileSync(path.join(directory, '.aiignore'), 'secrets/**\n');
    expect(() => loadPolicy(structured)).toThrowError(
      expect.objectContaining({ code: 'legacy_ignore_detected' })
    );
    expect(() => loadPolicy(path.join(directory, '.aiignore'))).toThrowError(
      expect.objectContaining({ code: 'legacy_ignore_filename' })
    );
    expect(() => loadPolicy(path.join(directory, '.AIIGNORE'))).toThrowError(
      expect.objectContaining({ code: 'legacy_ignore_filename' })
    );
  });
});
