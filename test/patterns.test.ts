import { describe, expect, it } from 'vitest';
import { PolicyError } from '../src/errors.js';
import {
  canonicalizeCandidatePath,
  canonicalizeUrl,
  matchEnvironmentPattern,
  matchFilePattern,
  matchNetworkPattern,
  parseNetworkPattern,
  replaceStringPattern,
  testStringPattern,
  validateEnvironmentPattern,
  validateFilePattern,
  validateStringPattern
} from '../src/patterns.js';

describe('portable pattern primitives', () => {
  it('normalizes platform path separators in candidates', () => {
    expect(canonicalizeCandidatePath('nested\\file.txt', '/workspace')).toBe('nested/file.txt');
    expect(canonicalizeCandidatePath('/workspace/nested/file.txt', '/workspace')).toBe('nested/file.txt');
  });

  it('matches directory suffix patterns and dotfiles', () => {
    expect(matchFilePattern('private', 'private/')).toBe(true);
    expect(matchFilePattern('private/nested/key', 'private/')).toBe(true);
    expect(matchFilePattern('.env', '**/.env')).toBe(true);
  });

  it('supports explicit ASCII-only case folding without Unicode widening', () => {
    expect(matchFilePattern('secrets/Key.txt', 'Secrets/**', false)).toBe(false);
    expect(matchFilePattern('secrets/Key.txt', 'Secrets/**', true)).toBe(true);
    expect(matchFilePattern('Ä/Key.txt', 'ä/**', true)).toBe(false);
    expect(matchEnvironmentPattern('Ä_TOKEN', 'ä_token', true)).toBe(false);
  });

  it('uses gitignore-compatible double-star segment semantics', () => {
    expect(matchFilePattern('a/b', 'a/**/b')).toBe(true);
    expect(matchFilePattern('a/nested/b', 'a/**/b')).toBe(true);
    expect(matchFilePattern('private', 'private/**')).toBe(true);
    expect(matchFilePattern('private/key', 'private/**')).toBe(true);
    expect(matchFilePattern('pre-x-post', 'pre**post')).toBe(true);
    expect(matchFilePattern('pre/x/post', 'pre**post')).toBe(false);
  });

  it('rejects parent patterns, pattern backslashes, and environment separators', () => {
    expect(() => validateFilePattern('../secret', 'test')).toThrow(/parent traversal/u);
    expect(() => validateFilePattern('a\\b', 'test')).toThrow(/backslashes/u);
    expect(() => validateEnvironmentPattern('A/B', 'test')).toThrow(/separators/u);
    expect(() => validateEnvironmentPattern('A**', 'test')).toThrow(/\*\*/u);
    expect(() => validateFilePattern('!private/**', 'test')).toThrow(/negation/u);
    expect(() => validateFilePattern('file[', 'test')).toThrow(/unterminated character class/u);
    expect(() => validateFilePattern('[]', 'test')).toThrow(/invalid character class/u);
    expect(() => validateFilePattern('[z-a].txt', 'test')).toThrow(/descending/u);
    expect(() => validateFilePattern('[é].txt', 'test')).toThrow(/printable ASCII/u);
  });

  it('parses explicit ports and bracketed IPv6 network patterns', () => {
    const pattern = parseNetworkPattern('https://[2001:db8::1]:8443/**', 'test');
    expect(pattern.hostname).toBe('[2001:db8::1]');
    expect(pattern.port).toBe('8443');
    expect(matchNetworkPattern(canonicalizeUrl('https://[2001:db8::1]:8443/a'), pattern)).toBe(true);
  });

  it('normalizes valid ports and rejects out-of-range ports', () => {
    expect(parseNetworkPattern('https://example.com:0443/**', 'test').port).toBe('');
    expect(parseNetworkPattern('ws://example.com:080/**', 'test').port).toBe('');
    expect(parseNetworkPattern('https://example.com:00000/**', 'test').port).toBe('0');
    expect(() => parseNetworkPattern('https://example.com:65536/**', 'test')).toThrow(/port/u);
    expect(() => parseNetworkPattern('https://example.com:/**', 'test')).toThrow(/port/u);
    expect(() => parseNetworkPattern('https://[2001:db8::1]:99999/**', 'test')).toThrow(/port/u);
  });

  it('supports question-mark wildcards in network paths without matching queries', () => {
    const pattern = parseNetworkPattern('https://example.com/users/?/profile', 'test');
    expect(matchNetworkPattern(canonicalizeUrl('https://example.com/users/a/profile?ignored=yes'), pattern)).toBe(true);
    expect(matchNetworkPattern(canonicalizeUrl('https://example.com/users/ab/profile'), pattern)).toBe(false);
  });

  it('lets a terminal network double-star consume zero complete path segments', () => {
    const pattern = parseNetworkPattern('https://example.com/private/**', 'test');
    expect(matchNetworkPattern(canonicalizeUrl('https://example.com/private'), pattern)).toBe(true);
    expect(matchNetworkPattern(canonicalizeUrl('https://example.com/private/item'), pattern)).toBe(true);
  });

  it('normalizes IDNs and rejects ambiguous network patterns', () => {
    const pattern = parseNetworkPattern('https://bücher.example/**', 'test');
    expect(pattern.hostname).toBe('xn--bcher-kva.example');
    expect(matchNetworkPattern(canonicalizeUrl('https://xn--bcher-kva.example/a'), pattern)).toBe(true);
    expect(() => parseNetworkPattern('https://exa*mple.com/**', 'test')).toThrow(/wildcard/u);
    expect(() => parseNetworkPattern('https://example.com:*/**', 'test')).toThrow(/ports/u);
    expect(() => parseNetworkPattern('https://[2001:db8::1/**', 'test')).toThrow(/IPv6/u);
    expect(() => parseNetworkPattern('https://2001:db8::1/**', 'test')).toThrow(/IPv6/u);
    expect(() => parseNetworkPattern('https://*.127.0.0.1/**', 'test')).toThrow(/IP literal/u);
    expect(() => parseNetworkPattern('https://**.[2001:db8::1]/**', 'test')).toThrow(/IP literal/u);
    expect(() => parseNetworkPattern('https://example.com?discarded/**', 'test')).toThrow(
      /query markers/u
    );
    expect(() => parseNetworkPattern('https://example.com\\discarded/**', 'test')).toThrow(
      /backslashes/u
    );
    expect(() => parseNetworkPattern('https://example.com\t/**', 'test')).toThrow(/whitespace/u);
    for (const host of [
      '%65xample.com',
      'example%2ecom',
      'example..com',
      '-bad.com',
      'bad-.com',
      'bad_com'
    ]) {
      expect(() => parseNetworkPattern(`https://${host}/**`, 'test')).toThrow(/hostname|DNS/u);
    }
  });

  it('rejects unsupported candidate URL authority and protocol forms', () => {
    expect(() => canonicalizeUrl('not a URL')).toThrowError(PolicyError);
    expect(() => canonicalizeUrl('ftp://example.com/a')).toThrow(/unsupported/u);
    expect(() => canonicalizeUrl('https://user:pass@example.com/a')).toThrow(/userinfo/u);
    expect(() => canonicalizeUrl('https://@example.com/a')).toThrow(/userinfo/u);
    expect(() => canonicalizeUrl(' https:\t//@example.com/a ')).toThrow(/whitespace|control/u);
    expect(() => canonicalizeUrl('https:/example.com/a')).toThrow(/scheme:\/\/authority/u);
    expect(() => canonicalizeUrl('https:///example.com/a')).toThrow(/scheme:\/\/authority/u);
    expect(() => canonicalizeUrl('https://example.com\\private')).toThrow(/backslashes/u);
    expect(() => canonicalizeUrl('https://example.com:/private')).toThrow(/port/u);
    expect(() => canonicalizeUrl('https://example.com/a#')).toThrow(/fragments/u);
    expect(() => canonicalizeUrl('https://%65xample.com/a')).toThrow(/hostname/u);
    expect(() => canonicalizeUrl('http://2130706433/status')).toThrow(/hostname/u);
    expect(canonicalizeUrl('https://example.com/users/@me').pathname).toBe('/users/@me');
    expect(parseNetworkPattern('https://example.com/users/@me/**', 'test').pathname).toBe(
      '/users/@me/**'
    );
  });

  it('normalizes percent escapes and rejects ambiguous encoded separators', () => {
    expect(canonicalizeUrl('https://example.com/%7euser').pathname).toBe('/%7Euser');
    expect(parseNetworkPattern('https://example.com/%7e*/**', 'test').pathname).toBe('/%7E*/**');
    expect(() => canonicalizeUrl('https://example.com/safe%2fprivate')).toThrow(/separators/u);
    expect(() => canonicalizeUrl('https://example.com/%00')).toThrow(/NUL/u);
    expect(() => parseNetworkPattern('https://example.com/%5csecret', 'test')).toThrow(/separators/u);
    expect(() => parseNetworkPattern('https://example.com/%zz', 'test')).toThrow(/percent/u);
    expect(() => parseNetworkPattern('https://example.com/café', 'test')).toThrow(/ASCII/u);
  });

  it('tests and replaces literal, glob, and RE2 string patterns', () => {
    expect(testStringPattern('Value=secret', { type: 'literal', value: 'SECRET', caseSensitive: false })).toBe(true);
    expect(testStringPattern('Ä', { type: 'literal', value: 'ä', caseSensitive: false })).toBe(true);
    expect(
      replaceStringPattern(
        'SECRET then secret',
        { type: 'literal', value: 'secret', caseSensitive: false },
        'x'
      )
    ).toBe('x then x');
    expect(testStringPattern('prefix-ABC-123-suffix', { type: 'glob', value: '*ABC-???*' })).toBe(true);
    expect(testStringPattern('prefix-B-suffix', { type: 'glob', value: '*[A-C]*' })).toBe(true);
    expect(testStringPattern('prefix-Z-suffix', { type: 'glob', value: '*[!A-C]*' })).toBe(true);
    expect(testStringPattern('B', { type: 'glob', value: '[!A-C]' })).toBe(false);
    expect(testStringPattern('literal-[', { type: 'glob', value: '*[*' })).toBe(true);
    expect(testStringPattern('KEY-42', { type: 'regex', value: 'KEY-[0-9]+' })).toBe(true);
    expect(
      replaceStringPattern('SECRET SECRET', { type: 'regex', value: '(SECRET)' }, '$1/$&/\\')
    ).toBe('$1/$&/\\ $1/$&/\\');
    expect(
      replaceStringPattern('🙂SECRET🙂', { type: 'literal', value: 'SECRET' }, '[X]')
    ).toBe('🙂[X]🙂');
  });

  it('rejects contextual zero-width string matches', () => {
    for (const value of ['\\b', '\\B', '^', '$', 'a*\\b', '(?:x|\\b)']) {
      expect(() => validateStringPattern({ type: 'regex', value }, 'test')).toThrow(
        /must not match the empty string/u
      );
    }
    expect(() =>
      validateStringPattern({ type: 'regex', value: '^SECRET$' }, 'test')
    ).not.toThrow();
  });

  it('rejects empty and invalid string patterns', () => {
    expect(() => validateStringPattern({ type: 'literal', value: '' }, 'test')).toThrow(/non-empty/u);
    expect(() => validateStringPattern({ type: 'regex', value: '(?=x)' }, 'test')).toThrow(/RE2/u);
    expect(() => validateStringPattern({ type: 'regex', value: 'a*' }, 'test')).toThrow(
      /empty string/u
    );
    expect(() => validateStringPattern({ type: 'glob', value: '*' }, 'test')).toThrow(
      /empty string/u
    );
  });

  it('bounds redaction expansion and replacement counts', () => {
    expect(() =>
      replaceStringPattern('X'.repeat(20_000), { type: 'literal', value: 'X' }, 'R'.repeat(1024))
    ).toThrow(/exceeds .* bytes/u);
    expect(() =>
      replaceStringPattern('X'.repeat(100_001), { type: 'literal', value: 'X' }, '')
    ).toThrow(/exceeds .* replacements/u);
  });
});
