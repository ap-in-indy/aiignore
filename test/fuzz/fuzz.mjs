import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  FILE_OPERATIONS,
  STRING_SCOPES,
  PolicyEngine,
  PolicyError,
  parsePolicy
} from '../../dist/index.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const options = parseArguments(process.argv.slice(2));
const dictionary = loadDictionary(path.join(root, 'test/fuzz/aiignore.dict'));
const parserCorpus = loadParserCorpus();
const mutationParserCorpus = parserCorpus.filter((bytes) => bytes.byteLength <= 64 * 1024);
assert.ok(mutationParserCorpus.length > 0);

function runTarget(name, seed, target) {
  if (options.target !== 'all' && options.target !== name) return;
  if (name === 'parser') exerciseParserCorpus();
  if (name === 'decision') exerciseDecisionSurface();
  const random = new Random(seed);
  for (let iteration = 0; iteration < options.iterations; iteration += 1) {
    try {
      target(random, iteration);
    } catch (error) {
      const message = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
      process.stderr.write(
        `not ok - fuzz target ${name} seed ${formatSeed(options.seed)} iteration ${iteration}: ${message}\n`
      );
      process.stderr.write(
        `reproduce: npm run fuzz:smoke -- --seed ${formatSeed(options.seed)} --iterations ${iteration + 1} --target ${name}\n`
      );
      return false;
    }
  }
  return true;
}

function fuzzParser(random, iteration) {
  const seed = mutationParserCorpus[iteration % mutationParserCorpus.length];
  const bytes = mutate(seed, random);
  exerciseParserBytes(bytes);
}

function exerciseParserCorpus() {
  for (const bytes of parserCorpus) exerciseParserBytes(bytes);
}

function exerciseParserBytes(bytes) {
  let first;
  try {
    first = parsePolicy(new Uint8Array(bytes), '<fuzz>');
  } catch (error) {
    assertPolicyError(error);
    return;
  }

  assert.equal(first.digest, createHash('sha256').update(bytes).digest('hex'));
  assert.equal(first.source, '<fuzz>');
  assertDeepFrozen(first);
  const second = parsePolicy(new Uint8Array(bytes), '<fuzz>');
  assert.equal(second.digest, first.digest);
  assert.deepEqual(second.document, first.document);

  const engine = new PolicyEngine(first);
  assertDeterministicDecision('file', () => engine.decideFile('fuzz/smoke.txt', 'read'), first.digest);
  assertDeterministicDecision('environment', () => engine.decideEnvironment('FUZZ_SMOKE'), first.digest);
  assertDeterministicDecision('network', () => engine.decideNetwork('https://example.com/fuzz'), first.digest);
  assertDeterministicDecision('string', () => engine.decideString('fuzz-smoke', 'log'), first.digest);
}

const decisionPolicy = parsePolicy(
  readFileSync(path.join(root, 'examples/complete.aiignore.yaml')),
  path.join(root, 'examples/complete.aiignore.yaml')
);
const decisionEngine = new PolicyEngine(decisionPolicy);

function exerciseDecisionSurface() {
  for (const operation of FILE_OPERATIONS) {
    for (const caseInsensitive of [false, true]) {
      assertDeterministicDecision('file', () =>
        decisionEngine.decideFile('fuzz/smoke.txt', operation, decisionPolicy.root, caseInsensitive)
      );
    }
  }
  for (const caseInsensitive of [false, true]) {
    assertDeterministicDecision('environment', () =>
      decisionEngine.decideEnvironment('FUZZ_SMOKE', caseInsensitive)
    );
  }
  assertDeterministicDecision('network', () =>
    decisionEngine.decideNetwork('https://example.com/fuzz')
  );
  for (const scope of STRING_SCOPES) {
    assertDeterministicDecision('string', () => decisionEngine.decideString('fuzz-smoke', scope));
  }
  const environment = Object.create(null);
  environment['__proto__'] = 'prototype-value';
  environment['constructor'] = 'constructor-value';
  assertEnvironmentFilter(environment);
}

function fuzzDecision(random) {
  const candidate = randomCandidate(random);
  switch (random.integer(5)) {
    case 0: {
      const operation = FILE_OPERATIONS[random.integer(FILE_OPERATIONS.length)];
      const caseInsensitive = random.boolean();
      assertDeterministicDecision('file', () =>
        decisionEngine.decideFile(candidate, operation, decisionPolicy.root, caseInsensitive)
      );
      break;
    }
    case 1: {
      const caseInsensitive = random.boolean();
      assertDeterministicDecision('environment', () =>
        decisionEngine.decideEnvironment(candidate, caseInsensitive)
      );
      break;
    }
    case 2:
      assertDeterministicDecision('network', () => decisionEngine.decideNetwork(candidate));
      break;
    case 3: {
      const scope = STRING_SCOPES[random.integer(STRING_SCOPES.length)];
      assertDeterministicDecision('string', () => decisionEngine.decideString(candidate, scope));
      break;
    }
    default: {
      const environment = Object.create(null);
      environment[candidate] = randomCandidate(random);
      environment['__proto__'] = 'prototype-value';
      environment['constructor'] = 'constructor-value';
      assertEnvironmentFilter(environment);
    }
  }
}

function assertEnvironmentFilter(environment) {
  const captured = capture(() => decisionEngine.filterEnvironment(environment));
  const repeated = capture(() => decisionEngine.filterEnvironment(environment));
  assert.deepEqual(repeated, captured);
  if (!captured.ok) return;
  assert.equal(Object.getPrototypeOf(captured.value.environment), null);
  assert.equal(Object.getPrototypeOf(captured.value.decisions), null);
  assert.equal(Object.getPrototypeOf(captured.value.valueDecisions), null);
  for (const decision of Object.values(captured.value.decisions)) {
    assertDecision('environment', decision);
  }
  for (const decision of Object.values(captured.value.valueDecisions)) {
    assertDecision('string', decision);
  }
}

function assertDeterministicDecision(resource, operation, digest = decisionPolicy.digest) {
  const first = capture(operation);
  const second = capture(operation);
  assert.deepEqual(second, first);
  if (first.ok) assertDecision(resource, first.value, digest);
}

function capture(operation) {
  try {
    return { ok: true, value: operation() };
  } catch (error) {
    assertPolicyError(error);
    return { ok: false, errorCode: error.code };
  }
}

function assertDecision(resource, decision, digest = decisionPolicy.digest) {
  assert.equal(decision.resource, resource);
  assert.equal(decision.policyDigest, digest);
  assert.ok(['allow', 'deny', 'drop', 'redact', 'audit'].includes(decision.effect));
  assert.ok(decision.ruleId === null || typeof decision.ruleId === 'string');
  assert.ok(decision.matched === null || typeof decision.matched === 'string');
  assert.ok(decision.appliedRuleIds === undefined || Array.isArray(decision.appliedRuleIds));
  if (decision.appliedRuleIds) {
    assert.equal(new Set(decision.appliedRuleIds).size, decision.appliedRuleIds.length);
    assert.ok(decision.appliedRuleIds.every((id) => typeof id === 'string' && id.length > 0));
  }
  assert.ok(decision.output === undefined || typeof decision.output === 'string');
  assert.ok(decision.reason.length > 0);
}

function assertPolicyError(error) {
  if (!(error instanceof PolicyError)) throw error;
  assert.match(error.code, /^[a-z][a-z0-9_]*$/u);
  assert.ok(error.message.length > 0);
}

function assertDeepFrozen(value) {
  if (value === null || typeof value !== 'object') return;
  assert.equal(Object.isFrozen(value), true);
  for (const child of Object.values(value)) assertDeepFrozen(child);
}

function loadParserCorpus() {
  const vectors = JSON.parse(
    readFileSync(path.join(root, 'test/parser-conformance/v0.1.json'), 'utf8')
  );
  const corpus = [];
  let coveredCases = 0;
  for (const testCase of vectors.cases) {
    if (testCase.text !== undefined) {
      corpus.push(Buffer.from(testCase.text));
      coveredCases += 1;
    } else if (testCase.bytesBase64 !== undefined) {
      corpus.push(Buffer.from(testCase.bytesBase64, 'base64'));
      coveredCases += 1;
    } else if (testCase.repeat !== undefined) {
      corpus.push(Buffer.from(testCase.repeat.text.repeat(testCase.repeat.count)));
      coveredCases += 1;
    }
  }
  assert.equal(coveredCases, vectors.cases.length);
  for (const filename of [
    'examples/complete.aiignore.yaml',
    'profiles/recommended.aiignore.yaml'
  ]) {
    corpus.push(readFileSync(path.join(root, filename)));
  }
  assert.ok(corpus.length > 0);
  return corpus;
}

function loadDictionary(filename) {
  return readFileSync(filename, 'utf8')
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'))
    .map((line) => {
      const separator = line.indexOf('=');
      assert.ok(separator > 0, `invalid fuzz dictionary line: ${line}`);
      return Buffer.from(JSON.parse(line.slice(separator + 1)));
    });
}

function mutate(input, random) {
  let bytes = Buffer.from(input);
  switch (random.integer(9)) {
    case 0:
      if (bytes.length > 0) bytes[random.integer(bytes.length)] ^= 1 << random.integer(8);
      break;
    case 1:
      bytes = insert(bytes, random.integer(bytes.length + 1), randomBytes(random, 1 + random.integer(16)));
      break;
    case 2:
      if (bytes.length > 0) {
        const start = random.integer(bytes.length);
        const count = 1 + random.integer(Math.min(32, bytes.length - start));
        bytes = Buffer.concat([bytes.subarray(0, start), bytes.subarray(start + count)]);
      }
      break;
    case 3:
      if (bytes.length > 0) {
        const start = random.integer(bytes.length);
        const count = 1 + random.integer(Math.min(64, bytes.length - start));
        bytes = insert(bytes, random.integer(bytes.length + 1), bytes.subarray(start, start + count));
      }
      break;
    case 4:
      bytes = insert(bytes, random.integer(bytes.length + 1), dictionary[random.integer(dictionary.length)]);
      break;
    case 5:
      bytes = bytes.subarray(0, random.integer(bytes.length + 1));
      break;
    case 6:
      bytes = Buffer.concat([bytes, dictionary[random.integer(dictionary.length)]]);
      break;
    case 7:
      bytes = randomBytes(random, random.integer(1025));
      break;
    default:
      if (bytes.length > 1) {
        const left = random.integer(bytes.length);
        const right = random.integer(bytes.length);
        [bytes[left], bytes[right]] = [bytes[right], bytes[left]];
      }
  }
  return bytes.length <= 64 * 1024 ? bytes : bytes.subarray(0, 64 * 1024);
}

function insert(bytes, offset, addition) {
  return Buffer.concat([bytes.subarray(0, offset), addition, bytes.subarray(offset)]);
}

function randomBytes(random, length) {
  const bytes = Buffer.allocUnsafe(length);
  for (let index = 0; index < length; index += 1) bytes[index] = random.integer(256);
  return bytes;
}

const candidateTokens = [
  '', '/', '\\', '..', '.', '%', '%2f', '%5c', '?', '#', '*', '**', '[', ']', '\0',
  '\t', '\r', '\n', 'https://', 'file://', '127.0.0.1', '[::1]', 'é', 'İ', 'ß', '中',
  '😀', '\ud800', '\udfff', '__proto__', 'constructor'
];

function randomCandidate(random) {
  const parts = [];
  const count = random.integer(65);
  for (let index = 0; index < count; index += 1) {
    if (random.integer(4) === 0) {
      parts.push(candidateTokens[random.integer(candidateTokens.length)]);
    } else {
      parts.push(String.fromCharCode(random.integer(0x10000)));
    }
  }
  return parts.join('').slice(0, 512);
}

function parseArguments(args) {
  const result = { iterations: 2000, seed: 0xa11a0e01, target: 'all' };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    const value = args[index + 1];
    if (argument === '--iterations' && value !== undefined) {
      result.iterations = parsePositiveInteger(value, '--iterations');
      index += 1;
    } else if (argument === '--seed' && value !== undefined) {
      result.seed = parseSeed(value);
      index += 1;
    } else if (argument === '--target' && value !== undefined) {
      if (!['all', 'parser', 'decision'].includes(value)) throw new Error(`invalid target: ${value}`);
      result.target = value;
      index += 1;
    } else {
      throw new Error(`unknown or incomplete fuzz argument: ${argument}`);
    }
  }
  if (result.iterations > 1_000_000) throw new Error('--iterations exceeds 1000000');
  return result;
}

function parsePositiveInteger(value, label) {
  if (!/^[1-9][0-9]*$/u.test(value)) throw new Error(`${label} must be a positive integer`);
  return Number(value);
}

function parseSeed(value) {
  if (!/^(?:0x[a-f0-9]+|[0-9]+)$/iu.test(value)) throw new Error('--seed must be uint32 decimal or hex');
  const seed = Number(value);
  if (!Number.isSafeInteger(seed) || seed < 0 || seed > 0xffffffff) {
    throw new Error('--seed must be uint32 decimal or hex');
  }
  return seed >>> 0;
}

function formatSeed(seed) {
  return `0x${(seed >>> 0).toString(16).padStart(8, '0')}`;
}

class Random {
  constructor(seed) {
    this.state = seed >>> 0 || 0x6d2b79f5;
  }

  next() {
    let value = this.state;
    value ^= value << 13;
    value ^= value >>> 17;
    value ^= value << 5;
    this.state = value >>> 0;
    return this.state;
  }

  integer(maximum) {
    assert.ok(Number.isSafeInteger(maximum) && maximum > 0);
    return Math.floor((this.next() / 0x100000000) * maximum);
  }

  boolean() {
    return (this.next() & 1) === 1;
  }
}

const parserPassed = runTarget('parser', options.seed ^ 0xa10a10a1, fuzzParser);
const decisionPassed = runTarget('decision', options.seed ^ 0xdec1de01, fuzzDecision);
if (parserPassed === false || decisionPassed === false) process.exit(1);

process.stdout.write(
  `ok - deterministic fuzz seed ${formatSeed(options.seed)} ${options.iterations} iterations per selected target\n`
);
