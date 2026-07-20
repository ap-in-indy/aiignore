#!/usr/bin/env node
import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync
} from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const DEFAULT_ORIGIN = 'https://ap-in-indy.github.io/aiignore/';
const MAX_FILE_BYTES = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES = 64 * 1024 * 1024;
const MAX_FILES = 256;

export async function verifyPublication(options = {}) {
  const origin = canonicalOrigin(options.origin ?? DEFAULT_ORIGIN);
  const siteDirectory = path.resolve(options.siteDirectory ?? 'site-dist');
  const fetchImpl = options.fetchImpl ?? fetch;
  const checksumBytes = readBoundedFile(
    path.join(siteDirectory, 'SHA256SUMS'),
    'local SHA256SUMS'
  );
  const entries = parseChecksums(checksumBytes.toString('utf8'));
  const publishedChecksums = await fetchBytes(
    new URL('SHA256SUMS', origin),
    fetchImpl,
    MAX_FILE_BYTES
  );
  if (!publishedChecksums.equals(checksumBytes)) {
    throw new Error('published SHA256SUMS does not match the reviewed site build');
  }

  let localTotal = checksumBytes.byteLength;
  let publishedTotal = publishedChecksums.byteLength;
  for (const { filename, sha256 } of entries) {
    const localPath = path.join(siteDirectory, ...filename.split('/'));
    const localBytes = readBoundedFile(localPath, `local ${filename}`);
    localTotal += localBytes.byteLength;
    if (localTotal > MAX_TOTAL_BYTES) {
      throw new Error(`local publication exceeds ${MAX_TOTAL_BYTES} aggregate bytes`);
    }
    assertDigest(localBytes, sha256, `local ${filename}`);
    const remainingPublishedBytes = MAX_TOTAL_BYTES - publishedTotal;
    if (remainingPublishedBytes <= 0) {
      throw new Error(`published artifacts exceed ${MAX_TOTAL_BYTES} aggregate bytes`);
    }
    const publishedBytes = await fetchBytes(
      new URL(filename.split('/').map(encodeURIComponent).join('/'), origin),
      fetchImpl,
      Math.min(MAX_FILE_BYTES, remainingPublishedBytes)
    );
    publishedTotal += publishedBytes.byteLength;
    assertDigest(publishedBytes, sha256, `published ${filename}`);
  }
  return { origin: origin.href, files: entries.length };
}

function readBoundedFile(filename, label) {
  const pathState = lstatSync(filename);
  if (!pathState.isFile() || pathState.size > MAX_FILE_BYTES) {
    throw new Error(`${label} exceeds ${MAX_FILE_BYTES} bytes or is not a file`);
  }
  const descriptor = openSync(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = fstatSync(descriptor);
    if (!before.isFile() || before.size > MAX_FILE_BYTES) {
      throw new Error(`${label} exceeds ${MAX_FILE_BYTES} bytes or is not a file`);
    }
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    if (!after.isFile() || after.size > MAX_FILE_BYTES || bytes.byteLength > MAX_FILE_BYTES) {
      throw new Error(`${label} exceeds ${MAX_FILE_BYTES} bytes or is not a file`);
    }
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}

function canonicalOrigin(value) {
  const origin = new URL(value);
  const hostname = origin.hostname.replace(/^\[|\]$/gu, '');
  const localHttp =
    origin.protocol === 'http:' && ['127.0.0.1', '::1', 'localhost'].includes(hostname);
  if (origin.protocol !== 'https:' && !localHttp) {
    throw new Error('publication origin must use HTTPS (loopback HTTP is allowed for tests)');
  }
  if (origin.username || origin.password || origin.search || origin.hash) {
    throw new Error('publication origin must not contain credentials, a query, or a fragment');
  }
  origin.pathname = `${origin.pathname.replace(/\/+$/u, '')}/`;
  return origin;
}

function parseChecksums(text) {
  if (!text.endsWith('\n')) throw new Error('SHA256SUMS must end with LF');
  const entries = text
    .split('\n')
    .filter(Boolean)
    .map((line) => {
      const match = /^([a-f0-9]{64}) {2}([A-Za-z0-9._/-]+)$/u.exec(line);
      if (!match) throw new Error('SHA256SUMS contains a malformed entry');
      const filename = match[2];
      if (
        !filename ||
        filename.startsWith('/') ||
        filename.includes('\\') ||
        filename.split('/').some((segment) => segment === '' || segment === '.' || segment === '..')
      ) {
        throw new Error('SHA256SUMS contains an unsafe path');
      }
      return { sha256: match[1], filename };
    });
  if (entries.length === 0 || entries.length > MAX_FILES) {
    throw new Error(`SHA256SUMS must contain between 1 and ${MAX_FILES} entries`);
  }
  if (new Set(entries.map(({ filename }) => filename)).size !== entries.length) {
    throw new Error('SHA256SUMS contains duplicate paths');
  }
  return entries;
}

async function fetchBytes(url, fetchImpl, maximumBytes) {
  const response = await fetchWithRetry(url, fetchImpl);
  if (!response.ok || response.redirected) {
    throw new Error(`published artifact is unavailable without redirects: ${url.href}`);
  }
  const contentLength = response.headers.get('content-length');
  if (contentLength && Number(contentLength) > maximumBytes) {
    throw new Error(`published artifact exceeds ${maximumBytes} bytes: ${url.href}`);
  }
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maximumBytes) {
      await reader.cancel();
      throw new Error(`published artifact exceeds ${maximumBytes} bytes: ${url.href}`);
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks, total);
}

async function fetchWithRetry(url, fetchImpl) {
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      const response = await fetchImpl(url, {
        redirect: 'error',
        signal: AbortSignal.timeout(15_000)
      });
      if (response.ok || response.status < 500 || attempt === 3) return response;
    } catch {
      if (attempt === 3) break;
    }
    await new Promise((resolve) => setTimeout(resolve, attempt * 250));
  }
  throw new Error(`cannot fetch published artifact: ${url.href}`);
}

function assertDigest(bytes, expected, label) {
  const actual = createHash('sha256').update(bytes).digest('hex');
  if (actual !== expected) throw new Error(`${label} SHA-256 mismatch`);
}

async function main() {
  const args = process.argv.slice(2);
  let origin = DEFAULT_ORIGIN;
  let siteDirectory = 'site-dist';
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === '--origin' && args[index + 1]) origin = args[++index];
    else if (args[index] === '--site-dir' && args[index + 1]) siteDirectory = args[++index];
    else throw new Error('usage: verify-publication.mjs [--origin URL] [--site-dir directory]');
  }
  const result = await verifyPublication({ origin, siteDirectory });
  process.stdout.write(`ok - published canonical site matches ${result.files} checksummed files\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
