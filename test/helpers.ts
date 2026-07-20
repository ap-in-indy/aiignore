import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { parsePolicy } from '../src/parser.js';

export function policy(body: string) {
  return parsePolicy(body, '/workspace/.aiignore.yaml');
}

export const BASE = `aiignore: "0.1"\n`;

export function createMinimalConformanceBundle(root: string, decisionSuiteCount = 1): string {
  const parserPath = 'test/parser-conformance/minimal.json';
  const decisionPath = 'test/conformance/minimal.json';
  const parser = `${JSON.stringify({
    revision: 'minimal-parser',
    uri: 'https://example.invalid/vectors/parser.json',
    cases: [{ id: 'valid-minimal', text: BASE, valid: true }]
  })}\n`;
  const decisions = Array.from({ length: decisionSuiteCount }, (_, index) => {
    const suffix = index === 0 ? '' : `-${index + 1}`;
    const relative = index === 0 ? decisionPath : `test/conformance/minimal${suffix}.json`;
    const uri = `https://example.invalid/vectors/decision${suffix}.json`;
    const bytes = `${JSON.stringify({
      revision: `minimal-decision${suffix}`,
      uri,
      policy: BASE,
      cases: [
        {
          id: `default-file-allow${suffix}`,
          resource: 'file',
          candidate: 'README.md',
          operation: 'read',
          effect: 'allow',
          ruleId: null
        }
      ]
    })}\n`;
    return { index, relative, uri, bytes };
  });
  for (const [relative, bytes] of [
    [parserPath, parser],
    ...decisions.map(({ relative, bytes }) => [relative, bytes] as const)
  ] as const) {
    const destination = path.join(root, relative);
    mkdirSync(path.dirname(destination), { recursive: true });
    writeFileSync(destination, bytes);
  }
  const manifestPath = path.join(root, 'conformance/manifest-v0.1.json');
  mkdirSync(path.dirname(manifestPath), { recursive: true });
  writeFileSync(
    manifestPath,
    `${JSON.stringify({
      formatVersion: '0.1',
      specification: '0.1',
      release: '0.1.0-alpha.1',
      status: 'experimental',
      uri: 'https://ap-in-indy.github.io/aiignore/conformance/0.1/manifest.json',
      artifacts: [
        {
          id: 'parser-minimal',
          role: 'parser-vectors',
          mediaType: 'application/json',
          path: parserPath,
          uri: 'https://example.invalid/vectors/parser.json',
          sha256: sha256(parser)
        },
        ...decisions.map(({ index, relative, uri, bytes }) => ({
          id: index === 0 ? 'decision-minimal' : `decision-minimal-${index + 1}`,
          role: 'decision-vectors',
          mediaType: 'application/json',
          path: relative,
          uri,
          sha256: sha256(bytes)
        }))
      ]
    })}\n`
  );
  return manifestPath;
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}
