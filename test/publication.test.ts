import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, symlinkSync, truncateSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { verifyPublication } from '../scripts/verify-publication.mjs';

describe('canonical publication verification', () => {
  it('requires every published byte to match the reviewed site checksums', async () => {
    const fixture = createSiteFixture();
    await expect(
      verifyPublication({
        origin: fixture.origin,
        siteDirectory: fixture.directory,
        fetchImpl: fixture.fetchImpl
      })
    ).resolves.toMatchObject({ files: 2 });
  });

  it('rejects a remotely modified artifact without echoing its bytes', async () => {
    const fixture = createSiteFixture();
    fixture.responses.set(`${fixture.origin}spec/0.1/aiignore.md`, Buffer.from('modified'));
    await expect(
      verifyPublication({
        origin: fixture.origin,
        siteDirectory: fixture.directory,
        fetchImpl: fixture.fetchImpl
      })
    ).rejects.toThrow('published spec/0.1/aiignore.md SHA-256 mismatch');
  });

  it('rejects checksum substitution before trusting individual artifacts', async () => {
    const fixture = createSiteFixture();
    fixture.responses.set(`${fixture.origin}SHA256SUMS`, Buffer.from('substituted\n'));
    await expect(
      verifyPublication({
        origin: fixture.origin,
        siteDirectory: fixture.directory,
        fetchImpl: fixture.fetchImpl
      })
    ).rejects.toThrow('published SHA256SUMS does not match');
  });

  it('rejects unsafe and duplicate checksum paths', async () => {
    const fixture = createSiteFixture();
    const digest = '0'.repeat(64);
    writeFileSync(path.join(fixture.directory, 'SHA256SUMS'), `${digest}  ../escape\n`);
    await expect(
      verifyPublication({
        origin: fixture.origin,
        siteDirectory: fixture.directory,
        fetchImpl: fixture.fetchImpl
      })
    ).rejects.toThrow('unsafe path');

    writeFileSync(
      path.join(fixture.directory, 'SHA256SUMS'),
      `${digest}  index.html\n${digest}  index.html\n`
    );
    await expect(
      verifyPublication({
        origin: fixture.origin,
        siteDirectory: fixture.directory,
        fetchImpl: fixture.fetchImpl
      })
    ).rejects.toThrow('duplicate paths');
  });

  it('requires HTTPS except for an explicit loopback test origin', async () => {
    const fixture = createSiteFixture();
    await expect(
      verifyPublication({
        origin: 'http://publication.example/',
        siteDirectory: fixture.directory,
        fetchImpl: fixture.fetchImpl
      })
    ).rejects.toThrow('must use HTTPS');
  });

  it('accepts a bracketed IPv6 loopback test origin', async () => {
    const fixture = createSiteFixture('http://[::1]/');
    await expect(
      verifyPublication({
        origin: fixture.origin,
        siteDirectory: fixture.directory,
        fetchImpl: fixture.fetchImpl
      })
    ).resolves.toMatchObject({ origin: fixture.origin, files: 2 });
  });

  it('rejects an oversized local artifact before reading it', async () => {
    const fixture = createSiteFixture();
    const filename = 'oversized.bin';
    const checksumBytes = Buffer.from(`${'0'.repeat(64)}  ${filename}\n`);
    writeFileSync(path.join(fixture.directory, 'SHA256SUMS'), checksumBytes);
    fixture.responses.set(`${fixture.origin}SHA256SUMS`, checksumBytes);
    const oversized = path.join(fixture.directory, filename);
    writeFileSync(oversized, '');
    truncateSync(oversized, 16 * 1024 * 1024 + 1);
    await expect(
      verifyPublication({
        origin: fixture.origin,
        siteDirectory: fixture.directory,
        fetchImpl: fixture.fetchImpl
      })
    ).rejects.toThrow('exceeds 16777216 bytes');
  });

  it('rejects an oversized checksum manifest before reading it', async () => {
    const fixture = createSiteFixture();
    truncateSync(path.join(fixture.directory, 'SHA256SUMS'), 16 * 1024 * 1024 + 1);
    await expect(
      verifyPublication({
        origin: fixture.origin,
        siteDirectory: fixture.directory,
        fetchImpl: fixture.fetchImpl
      })
    ).rejects.toThrow('local SHA256SUMS exceeds 16777216 bytes');
  });

  it.skipIf(process.platform === 'win32')('rejects a symlinked checksum manifest', async () => {
    const fixture = createSiteFixture();
    const manifest = path.join(fixture.directory, 'SHA256SUMS');
    const target = path.join(fixture.directory, 'manifest-target');
    writeFileSync(target, fixture.responses.get(`${fixture.origin}SHA256SUMS`)!);
    symlinkSync(target, `${manifest}.link`);
    const linkedDirectory = mkdtempSync(path.join(tmpdir(), 'aiignore-publication-link-'));
    symlinkSync(`${manifest}.link`, path.join(linkedDirectory, 'SHA256SUMS'));
    await expect(
      verifyPublication({
        origin: fixture.origin,
        siteDirectory: linkedDirectory,
        fetchImpl: fixture.fetchImpl
      })
    ).rejects.toThrow('not a file');
  });
});

function createSiteFixture(origin = 'https://publication.example/'): {
  directory: string;
  origin: string;
  responses: Map<string, Buffer>;
  fetchImpl: typeof fetch;
} {
  const directory = mkdtempSync(path.join(tmpdir(), 'aiignore-publication-'));
  const files = new Map<string, Buffer>([
    ['index.html', Buffer.from('<!doctype html><title>aiignore</title>\n')],
    ['spec/0.1/aiignore.md', Buffer.from('# aiignore fixture\n')]
  ]);
  const checksums = [...files]
    .map(
      ([filename, bytes]) =>
        `${createHash('sha256').update(bytes).digest('hex')}  ${filename}`
    )
    .sort()
    .join('\n');
  const checksumBytes = Buffer.from(`${checksums}\n`);
  for (const [filename, bytes] of files) {
    const destination = path.join(directory, ...filename.split('/'));
    mkdirSync(path.dirname(destination), { recursive: true });
    writeFileSync(destination, bytes);
  }
  writeFileSync(path.join(directory, 'SHA256SUMS'), checksumBytes);
  const responses = new Map<string, Buffer>(
    [...files].map(([filename, bytes]) => [`${origin}${filename}`, bytes])
  );
  responses.set(`${origin}SHA256SUMS`, checksumBytes);
  const fetchImpl = ((input: string | URL | Request) => {
    const url = input instanceof Request ? input.url : String(input);
    const bytes = responses.get(url);
    return Promise.resolve(
      bytes ? new Response(new Uint8Array(bytes)) : new Response('missing', { status: 404 })
    );
  }) as typeof fetch;
  return { directory, origin, responses, fetchImpl };
}
