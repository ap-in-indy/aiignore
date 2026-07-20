import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  type Stats
} from 'node:fs';
import path from 'node:path';
import { PolicyError } from './errors.js';

export interface BoundedFileReadOptions {
  maximumBytes: number;
  label: string;
  unreadableCode: string;
  notFileCode: string;
  tooLargeCode: string;
  changedCode: string;
}

/**
 * Reads one pathname without following symlinks and binds the returned bytes
 * to the same regular-file snapshot that was inspected before and after open.
 */
export function readBoundedRegularFile(
  filename: string,
  options: BoundedFileReadOptions
): Buffer {
  const absolutePath = path.resolve(filename);
  let initial: ReturnType<typeof lstatSync>;
  try {
    initial = lstatSync(absolutePath);
  } catch {
    throw new PolicyError(options.unreadableCode, `${options.label} is unavailable`);
  }
  assertRegularFile(initial, options, absolutePath);
  assertBounded(initial, options);

  let descriptor: number | undefined;
  try {
    descriptor = openSync(absolutePath, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const opened = fstatSync(descriptor);
    const linked = lstatSync(absolutePath);
    if (
      !opened.isFile() ||
      !linked.isFile() ||
      linked.isSymbolicLink() ||
      !sameFileSnapshot(initial, opened) ||
      !sameFileSnapshot(opened, linked)
    ) {
      throw new PolicyError(
        options.changedCode,
        `${options.label} changed while it was opened`
      );
    }
    assertBounded(opened, options);
    const bytes = readAtMost(descriptor, options.maximumBytes + 1);
    if (bytes.byteLength > options.maximumBytes) {
      throw new PolicyError(
        options.tooLargeCode,
        `${options.label} exceeds ${options.maximumBytes} bytes`
      );
    }
    const afterRead = fstatSync(descriptor);
    if (!sameFileSnapshot(opened, afterRead) || bytes.byteLength !== afterRead.size) {
      throw new PolicyError(options.changedCode, `${options.label} changed while it was read`);
    }
    return bytes;
  } catch (error) {
    if (error instanceof PolicyError) throw error;
    if (error instanceof Error && 'code' in error && error.code === 'ELOOP') {
      throw new PolicyError(
        options.notFileCode,
        `${absolutePath} is not a regular file (symlinks are not accepted)`
      );
    }
    throw new PolicyError(options.unreadableCode, `${options.label} cannot be read`);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

export function readAtMost(descriptor: number, maximumBytes: number): Buffer {
  const chunks: Buffer[] = [];
  let total = 0;
  while (total < maximumBytes) {
    const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, maximumBytes - total));
    const count = readSync(descriptor, chunk, 0, chunk.byteLength, null);
    if (count === 0) break;
    chunks.push(chunk.subarray(0, count));
    total += count;
  }
  return Buffer.concat(chunks, total);
}

function assertRegularFile(
  stat: Stats,
  options: BoundedFileReadOptions,
  absolutePath: string
): void {
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new PolicyError(
      options.notFileCode,
      `${absolutePath} is not a regular file (symlinks are not accepted)`
    );
  }
}

function assertBounded(stat: Stats, options: BoundedFileReadOptions): void {
  if (stat.size > options.maximumBytes) {
    throw new PolicyError(
      options.tooLargeCode,
      `${options.label} exceeds ${options.maximumBytes} bytes`
    );
  }
}

function sameFileSnapshot(left: Stats, right: Stats): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}
