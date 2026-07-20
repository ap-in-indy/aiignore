#!/usr/bin/env node
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const ALPHA_PATTERN = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-alpha\.([1-9][0-9]*)$/u;
const MAX_VERSION_LENGTH = 128;

export function assertAlphaAdvance(current, candidate) {
  const currentParts = parseAlpha(current, 'current alpha');
  const candidateParts = parseAlpha(candidate, 'candidate alpha');
  for (let index = 0; index < currentParts.length; index += 1) {
    if (candidateParts[index] > currentParts[index]) return;
    if (candidateParts[index] < currentParts[index]) {
      throw new Error(`${candidate} would move the alpha channel backward from ${current}`);
    }
  }
  throw new Error(`${candidate} does not advance the alpha channel beyond ${current}`);
}

function parseAlpha(value, label) {
  if (typeof value !== 'string' || value.length > MAX_VERSION_LENGTH) {
    throw new Error(`${label} is not a bounded alpha Semantic Version`);
  }
  const match = ALPHA_PATTERN.exec(value);
  if (!match) throw new Error(`${label} is not an alpha.N Semantic Version`);
  return match.slice(1).map((part) => BigInt(part));
}

function main() {
  const [current, candidate] = process.argv.slice(2);
  if (!current || !candidate || process.argv.length !== 4) {
    throw new Error('usage: validate-alpha-advance.mjs CURRENT_ALPHA CANDIDATE_ALPHA');
  }
  assertAlphaAdvance(current, candidate);
  process.stdout.write(`ok - ${candidate} advances alpha beyond ${current}\n`);
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
