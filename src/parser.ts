import { createHash } from 'node:crypto';
import { existsSync, lstatSync } from 'node:fs';
import path from 'node:path';
import { isAlias, isMap, isScalar, isSeq, parseDocument, type Node } from 'yaml';
import { PolicyError } from './errors.js';
import {
  isLegacyIgnoreFilename,
  LEGACY_IGNORE_FILENAME,
  POLICY_FILENAME
} from './constants.js';
import {
  parseNetworkPattern,
  validateEnvironmentPattern,
  validateFilePattern,
  validateStringPattern
} from './patterns.js';
import { validateSchema } from './schema.js';
import { readBoundedRegularFile } from './safe-file.js';
import type { LoadedPolicy, PolicyDocument, StringPattern } from './types.js';

export const MAX_POLICY_BYTES = 1024 * 1024;

export function loadPolicy(policyPath = POLICY_FILENAME): LoadedPolicy {
  const absolutePath = path.resolve(policyPath);
  if (isLegacyIgnoreFilename(path.basename(absolutePath))) {
    throw new PolicyError(
      'legacy_ignore_filename',
      `${absolutePath} is reserved for existing gitignore-style compatibility; structured policies use ${POLICY_FILENAME}`
    );
  }
  try {
    lstatSync(absolutePath);
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') {
      const legacyPath = path.join(path.dirname(absolutePath), LEGACY_IGNORE_FILENAME);
      if (path.basename(absolutePath) === POLICY_FILENAME && existsSync(legacyPath)) {
        throw new PolicyError(
          'legacy_ignore_detected',
          `${legacyPath} uses an existing gitignore-style compatibility filename; create ${absolutePath} for the structured policy`
        );
      }
      throw new PolicyError('policy_not_found', `policy file not found: ${absolutePath}`);
    }
    throw new PolicyError('policy_unreadable', `cannot inspect policy file: ${absolutePath}`);
  }
  return parsePolicy(
    readBoundedRegularFile(absolutePath, {
      maximumBytes: MAX_POLICY_BYTES,
      label: 'policy',
      unreadableCode: 'policy_unreadable',
      notFileCode: 'not_a_file',
      tooLargeCode: 'policy_too_large',
      changedCode: 'policy_changed_during_load'
    }),
    absolutePath
  );
}

export function loadPinnedPolicy(
  policyPath = POLICY_FILENAME,
  expectedDigest = process.env['AIIGNORE_POLICY_SHA256']
): LoadedPolicy {
  const policy = loadPolicy(policyPath);
  if (expectedDigest !== undefined && expectedDigest !== policy.digest) {
    throw new PolicyError(
      'policy_digest_mismatch',
      'policy bytes changed after the session digest was pinned'
    );
  }
  return policy;
}

export function parsePolicy(bytes: string | Uint8Array, source = '<memory>'): LoadedPolicy {
  const buffer = typeof bytes === 'string' ? Buffer.from(bytes, 'utf8') : Buffer.from(bytes);
  if (buffer.byteLength > MAX_POLICY_BYTES) {
    throw new PolicyError('policy_too_large', `policy exceeds ${MAX_POLICY_BYTES} bytes`);
  }
  const text = decodeUtf8(buffer);
  const document = parseDocument(text, {
    schema: 'core',
    strict: true,
    uniqueKeys: true
  });
  if (document.errors.length > 0) {
    const shown = document.errors
      .slice(0, 10)
      .map((error) => error.message.split('\n', 1)[0] ?? 'invalid YAML');
    throw new PolicyError(
      'invalid_yaml',
      `${shown.join('; ')}${document.errors.length > shown.length ? `; and ${document.errors.length - shown.length} more errors` : ''}`
    );
  }
  inspectYamlNode(document.contents, '$');
  const value = document.toJS({ maxAliasCount: 0 }) as unknown;
  const schemaErrors = validateSchema(value);
  if (schemaErrors.length > 0) {
    const formatted = schemaErrors
      .slice(0, 20)
      .map((error) => `${error.instancePath || '/'} ${error.message ?? 'is invalid'}`)
      .join('; ');
    const suffix = schemaErrors.length > 20 ? `; and ${schemaErrors.length - 20} more errors` : '';
    throw new PolicyError('schema_validation', `${formatted}${suffix}`);
  }
  const policy = value as PolicyDocument;
  validateSemantics(policy);
  const immutablePolicy = deepFreeze(policy);
  return Object.freeze({
    document: immutablePolicy,
    digest: createHash('sha256').update(buffer).digest('hex'),
    source,
    root: source === '<memory>' ? process.cwd() : path.dirname(path.resolve(source))
  });
}

function decodeUtf8(buffer: Buffer): string {
  const bom = Buffer.from([0xef, 0xbb, 0xbf]);
  const searchFrom = buffer.subarray(0, bom.length).equals(bom) ? bom.length : 0;
  if (buffer.indexOf(bom, searchFrom) >= 0) {
    throw new PolicyError(
      'invalid_encoding',
      'UTF-8 BOM is permitted only once at the beginning of the policy'
    );
  }
  const decoder = new TextDecoder('utf-8', { fatal: true });
  try {
    const decoded = decoder.decode(buffer);
    return decoded.startsWith('\uFEFF') ? decoded.slice(1) : decoded;
  } catch (error) {
    if (error instanceof PolicyError) throw error;
    throw new PolicyError('invalid_encoding', 'policy is not valid UTF-8');
  }
}

function inspectYamlNode(node: Node | null, location: string): void {
  if (node === null) return;
  if (isAlias(node)) throw new PolicyError('unsafe_yaml', `${location}: aliases are forbidden`);
  if ('anchor' in node && node.anchor) {
    throw new PolicyError('unsafe_yaml', `${location}: anchors are forbidden`);
  }
  if ('tag' in node && node.tag) {
    throw new PolicyError('unsafe_yaml', `${location}: explicit tags are forbidden`);
  }
  if (isMap(node)) {
    for (const pair of node.items) {
      if (!isScalar(pair.key) || typeof pair.key.value !== 'string') {
        throw new PolicyError('unsafe_yaml', `${location}: mapping keys must be strings`);
      }
      if (pair.key.value === '<<') {
        throw new PolicyError('unsafe_yaml', `${location}: merge keys are forbidden`);
      }
      inspectYamlNode(pair.value as Node | null, `${location}.${pair.key.value}`);
    }
  } else if (isSeq(node)) {
    node.items.forEach((item, index) => inspectYamlNode(item as Node | null, `${location}[${index}]`));
  }
}

function validateSemantics(policy: PolicyDocument): void {
  const ids = new Set<string>();
  const addId = (id: string): void => {
    if (ids.has(id)) throw new PolicyError('duplicate_rule_id', `duplicate rule id: ${id}`);
    ids.add(id);
  };

  for (const rule of policy.rules?.files ?? []) {
    addId(rule.id);
    rule.paths.forEach((pattern, index) => validateFilePattern(pattern, `${rule.id}.paths[${index}]`));
    rule.except?.forEach((pattern, index) =>
      validateFilePattern(pattern, `${rule.id}.except[${index}]`)
    );
  }
  for (const rule of policy.rules?.environment ?? []) {
    addId(rule.id);
    rule.names.forEach((pattern, index) =>
      validateEnvironmentPattern(pattern, `${rule.id}.names[${index}]`)
    );
    rule.except?.forEach((pattern, index) =>
      validateEnvironmentPattern(pattern, `${rule.id}.except[${index}]`)
    );
  }
  for (const rule of policy.rules?.network ?? []) {
    addId(rule.id);
    rule.urls.forEach((pattern, index) => parseNetworkPattern(pattern, `${rule.id}.urls[${index}]`));
    rule.except?.forEach((pattern, index) =>
      parseNetworkPattern(pattern, `${rule.id}.except[${index}]`)
    );
  }
  for (const rule of policy.rules?.strings ?? []) {
    addId(rule.id);
    validateStringPatterns(rule.patterns, `${rule.id}.patterns`);
    if (rule.except) validateStringPatterns(rule.except, `${rule.id}.except`);
  }
}

function validateStringPatterns(patterns: readonly StringPattern[], label: string): void {
  patterns.forEach((pattern, index) => validateStringPattern(pattern, `${label}[${index}]`));
}

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}
