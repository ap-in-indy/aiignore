import { closeSync, mkdtempSync, openSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { readAtMost, readBoundedRegularFile } from '../src/safe-file.js';

const options = {
  maximumBytes: 4,
  label: 'test input',
  unreadableCode: 'test_unreadable',
  notFileCode: 'test_not_file',
  tooLargeCode: 'test_too_large',
  changedCode: 'test_changed'
};

describe('bounded regular-file reads', () => {
  it('reads an unchanged regular file and returns exact bytes', () => {
    const directory = mkdtempSync(path.join(tmpdir(), 'aiignore-safe-read-'));
    const filename = path.join(directory, 'input');
    writeFileSync(filename, Buffer.from([0x00, 0x01, 0x02, 0x03]));
    expect(readBoundedRegularFile(filename, options)).toEqual(Buffer.from([0x00, 0x01, 0x02, 0x03]));

    const growingInput = path.join(directory, 'larger-input');
    writeFileSync(growingInput, '1234567890');
    const descriptor = openSync(growingInput, 'r');
    try {
      expect(readAtMost(descriptor, options.maximumBytes + 1).toString()).toBe('12345');
    } finally {
      closeSync(descriptor);
    }
  });

  it('rejects unavailable, non-file, and oversized inputs with stable codes', () => {
    const directory = mkdtempSync(path.join(tmpdir(), 'aiignore-safe-errors-'));
    expectPolicyCode(() => readBoundedRegularFile(path.join(directory, 'missing'), options), 'test_unreadable');
    expectPolicyCode(() => readBoundedRegularFile(directory, options), 'test_not_file');
    const oversized = path.join(directory, 'oversized');
    writeFileSync(oversized, '12345');
    expectPolicyCode(() => readBoundedRegularFile(oversized, options), 'test_too_large');
  });

  it.skipIf(process.platform === 'win32')('rejects symbolic-link inputs', () => {
    const directory = mkdtempSync(path.join(tmpdir(), 'aiignore-safe-link-'));
    const target = path.join(directory, 'target');
    const link = path.join(directory, 'link');
    writeFileSync(target, 'safe');
    symlinkSync(target, link);
    expectPolicyCode(() => readBoundedRegularFile(link, options), 'test_not_file');
  });
});

function expectPolicyCode(action: () => unknown, code: string): void {
  try {
    action();
    throw new Error('expected bounded file read to fail');
  } catch (error) {
    expect(error).toMatchObject({ code });
  }
}
