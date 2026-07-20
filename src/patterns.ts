import path from 'node:path';
import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';
import { minimatch } from 'minimatch';
import { RE2JS } from 're2js';
import { PolicyError } from './errors.js';
import type { StringPattern } from './types.js';

const GLOB_OPTIONS = {
  dot: true,
  nobrace: true,
  noext: true,
  nonegate: true,
  nocomment: true,
  windowsPathsNoEscape: true
} as const;

const EXTGLOB = /(^|[^\\])[?*+@!]\(/u;
const STRING_PATTERN_CACHE = new WeakMap<StringPattern, RE2JS>();
export const MAX_STRING_OUTPUT_BYTES = 16 * 1024 * 1024;
export const MAX_STRING_REPLACEMENTS = 100_000;

export function validateFilePattern(pattern: string, label: string): void {
  validateCommonGlob(pattern, label);
  if (pattern.includes('\\')) {
    throw new PolicyError('invalid_pattern', `${label}: backslashes are not allowed in policy patterns`);
  }
  const segments = pattern.split('/');
  if (segments.includes('..')) {
    throw new PolicyError('invalid_pattern', `${label}: parent traversal is not allowed`);
  }
}

export function validateEnvironmentPattern(pattern: string, label: string): void {
  validateCommonGlob(pattern, label);
  if (pattern.includes('/') || pattern.includes('**') || pattern.includes('\\')) {
    throw new PolicyError(
      'invalid_pattern',
      `${label}: environment patterns cannot contain separators, backslashes, or **`
    );
  }
}

function validateCommonGlob(pattern: string, label: string): void {
  if (pattern.length === 0 || pattern.includes('\0')) {
    throw new PolicyError('invalid_pattern', `${label}: pattern must be non-empty and contain no NUL`);
  }
  if (pattern.includes('{') || pattern.includes('}') || EXTGLOB.test(pattern)) {
    throw new PolicyError('invalid_pattern', `${label}: brace expansion and extglobs are not portable`);
  }
  if (pattern.startsWith('!')) {
    throw new PolicyError('invalid_pattern', `${label}: leading negation is not portable`);
  }
  validateCharacterClasses(pattern, label);
  try {
    minimatch('', pattern, GLOB_OPTIONS);
  } catch (error) {
    throw new PolicyError('invalid_pattern', `${label}: ${errorMessage(error)}`);
  }
}

export function normalizeFilePattern(pattern: string): string {
  let normalized = pattern.startsWith('/') ? pattern.slice(1) : pattern;
  if (normalized.endsWith('/')) normalized += '**';
  return normalized;
}

export function canonicalizeCandidatePath(candidate: string, root: string): string {
  if (candidate.length === 0 || candidate.includes('\0')) {
    throw new PolicyError('invalid_path', 'candidate path must be non-empty and contain no NUL');
  }
  const portableCandidate = candidate.replace(/\\/gu, '/');
  const absoluteRoot = path.resolve(root);
  const absoluteCandidate = path.isAbsolute(portableCandidate)
    ? path.resolve(portableCandidate)
    : path.resolve(absoluteRoot, portableCandidate);
  const relative = path.relative(absoluteRoot, absoluteCandidate);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new PolicyError('path_escape', 'candidate path escapes policy root');
  }
  return relative.split(path.sep).join('/') || '.';
}

export function matchFilePattern(
  candidate: string,
  pattern: string,
  caseInsensitive = false
): boolean {
  const comparableCandidate = caseInsensitive ? asciiFold(candidate) : candidate;
  const comparablePattern = caseInsensitive ? asciiFold(pattern) : pattern;
  const portablePattern = comparablePattern.startsWith('/') ? comparablePattern.slice(1) : comparablePattern;
  if (portablePattern.endsWith('/')) {
    const directory = portablePattern.slice(0, -1);
    return (
      directory === '' ||
      comparableCandidate === directory ||
      minimatch(comparableCandidate, `${directory}/**`, GLOB_OPTIONS)
    );
  }
  return matchPortableGlob(
    comparableCandidate,
    normalizeFilePattern(comparablePattern)
  );
}

export function matchEnvironmentPattern(
  name: string,
  pattern: string,
  caseInsensitive = false
): boolean {
  return minimatch(
    caseInsensitive ? asciiFold(name) : name,
    caseInsensitive ? asciiFold(pattern) : pattern,
    GLOB_OPTIONS
  );
}

export function validateEnvironmentName(name: string): void {
  if (name.length === 0 || name.includes('\0') || name.includes('=')) {
    throw new PolicyError(
      'invalid_environment_name',
      'environment name must be non-empty and contain neither NUL nor ='
    );
  }
}

export interface ParsedNetworkPattern {
  original: string;
  scheme: 'http' | 'https' | 'ws' | 'wss';
  hostname: string;
  hostnameMode: 'exact' | 'subdomains' | 'apex-and-subdomains';
  port: string;
  pathname: string;
}

export interface CanonicalUrl {
  original: string;
  scheme: 'http' | 'https' | 'ws' | 'wss';
  hostname: string;
  port: string;
  pathname: string;
}

export function parseNetworkPattern(pattern: string, label: string): ParsedNetworkPattern {
  if (pattern.includes('#')) {
    throw new PolicyError('invalid_network_pattern', `${label}: fragments are forbidden`);
  }
  const match = /^(https?|wss?):\/\/([^/]+)(\/.*)$/u.exec(pattern);
  if (!match) {
    throw new PolicyError(
      'invalid_network_pattern',
      `${label}: expected scheme://authority/path-pattern`
    );
  }
  const scheme = match[1] as ParsedNetworkPattern['scheme'];
  const authority = match[2] ?? '';
  const pathname = match[3] ?? '';
  if (
    authority.includes('?') ||
    authority.includes('\\') ||
    [...authority].some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint <= 0x20 || codePoint === 0x7f;
    })
  ) {
    throw new PolicyError(
      'invalid_network_pattern',
      `${label}: authority must not contain query markers, whitespace, control characters, or backslashes`
    );
  }
  if (authority.includes('@')) {
    throw new PolicyError('invalid_network_pattern', `${label}: userinfo is forbidden`);
  }
  if (/^\*{1,2}\.\[/u.test(authority)) {
    throw new PolicyError('invalid_network_pattern', `${label}: wildcard IP literals are forbidden`);
  }
  validateFilePattern(pathname, `${label} path`);
  if (/[^\x20-\x7e]/u.test(pathname)) {
    throw new PolicyError(
      'invalid_network_pattern',
      `${label}: network path patterns must be ASCII; use UTF-8 percent encoding`
    );
  }
  const normalizedPathname = normalizePercentEncoding(pathname, 'invalid_network_pattern', label);
  rejectEncodedSeparators(normalizedPathname, 'invalid_network_pattern', label);

  const { hostname: rawHostname, port } = splitAuthority(authority, label);
  let hostnameMode: ParsedNetworkPattern['hostnameMode'] = 'exact';
  let hostname = rawHostname;
  if (hostname.startsWith('**.')) {
    hostnameMode = 'apex-and-subdomains';
    hostname = hostname.slice(3);
  } else if (hostname.startsWith('*.')) {
    hostnameMode = 'subdomains';
    hostname = hostname.slice(2);
  }
  if (hostname.includes('*') || hostname.length === 0) {
    throw new PolicyError('invalid_network_pattern', `${label}: wildcard must be a leading *. or **.`);
  }

  const normalizedHostname = normalizeHostname(hostname, label);
  const ipLiteral = normalizedHostname.startsWith('[')
    ? normalizedHostname.slice(1, -1)
    : normalizedHostname;
  if (hostnameMode !== 'exact' && isIP(ipLiteral) !== 0) {
    throw new PolicyError('invalid_network_pattern', `${label}: wildcard IP literals are forbidden`);
  }
  return {
    original: pattern,
    scheme,
    hostname: normalizedHostname,
    hostnameMode,
    port: normalizePort(scheme, port),
    pathname: normalizedPathname
  };
}

export function canonicalizeUrl(candidate: string): CanonicalUrl {
  if (
    candidate !== candidate.trim() ||
    candidate.includes('\\') ||
    [...candidate].some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint <= 0x1f || codePoint === 0x7f;
    })
  ) {
    throw new PolicyError(
      'invalid_url',
      'URL must not contain surrounding whitespace, control characters, or backslashes'
    );
  }
  let url: URL;
  try {
    url = new URL(candidate);
  } catch (error) {
    throw new PolicyError('invalid_url', `invalid URL: ${errorMessage(error)}`);
  }
  const scheme = url.protocol.slice(0, -1);
  if (!['http', 'https', 'ws', 'wss'].includes(scheme)) {
    throw new PolicyError('invalid_url', `unsupported URL scheme: ${url.protocol}`);
  }
  if (!/^(?:https?|wss?):\/\/[^/?#\\]/iu.test(candidate)) {
    throw new PolicyError('invalid_url', 'URL must use scheme://authority syntax');
  }
  // Inspect the lexical authority so empty userinfo (for example
  // https://@host) cannot disappear during WHATWG normalization.
  const rawAuthority = /^(?:https?|wss?):\/\/([^/?#]*)/iu.exec(candidate)?.[1] ?? '';
  if (rawAuthority.endsWith(':')) {
    throw new PolicyError('invalid_url', 'an explicit URL port cannot be empty');
  }
  if (rawAuthority.includes('@') || url.username || url.password || candidate.includes('#')) {
    throw new PolicyError('invalid_url', 'URL userinfo and fragments are forbidden');
  }
  const lexicalHostname = candidateAuthorityHostname(rawAuthority);
  const normalizedHostname = normalizeHostnameValue(
    lexicalHostname,
    'URL hostname',
    'invalid_url'
  );
  if (url.hostname.toLowerCase().replace(/\.$/u, '') !== normalizedHostname) {
    throw new PolicyError('invalid_url', 'URL hostname was reinterpreted during normalization');
  }
  const pathname = normalizePercentEncoding(url.pathname, 'invalid_url', 'URL path');
  rejectEncodedSeparators(pathname, 'invalid_url', 'URL path');
  return {
    original: candidate,
    scheme: scheme as CanonicalUrl['scheme'],
    hostname: normalizedHostname,
    port: normalizePort(scheme as CanonicalUrl['scheme'], url.port),
    pathname
  };
}

export function matchNetworkPattern(candidate: CanonicalUrl, pattern: ParsedNetworkPattern): boolean {
  if (candidate.scheme !== pattern.scheme || candidate.port !== pattern.port) return false;
  const hostnameMatches =
    pattern.hostnameMode === 'exact'
      ? candidate.hostname === pattern.hostname
      : pattern.hostnameMode === 'subdomains'
        ? candidate.hostname.endsWith(`.${pattern.hostname}`)
        : candidate.hostname === pattern.hostname || candidate.hostname.endsWith(`.${pattern.hostname}`);
  return hostnameMatches && matchPortableGlob(candidate.pathname, pattern.pathname);
}

function matchPortableGlob(candidate: string, pattern: string): boolean {
  if (pattern.endsWith('/**') && candidate === pattern.slice(0, -3)) return true;
  return minimatch(candidate, pattern, GLOB_OPTIONS);
}

function splitAuthority(authority: string, label: string): { hostname: string; port: string } {
  if (authority.startsWith('[')) {
    const end = authority.indexOf(']');
    if (end < 0) throw new PolicyError('invalid_network_pattern', `${label}: malformed IPv6 literal`);
    const hostname = authority.slice(0, end + 1);
    const rest = authority.slice(end + 1);
    if (rest && !/^:\d+$/u.test(rest)) {
      throw new PolicyError('invalid_network_pattern', `${label}: invalid port`);
    }
    return { hostname, port: canonicalizePort(rest.slice(1), label) };
  }
  const pieces = authority.split(':');
  if (pieces.length > 2) {
    throw new PolicyError('invalid_network_pattern', `${label}: IPv6 literals must use brackets`);
  }
  const hostname = pieces[0] ?? '';
  const port = pieces[1] ?? '';
  if (pieces.length === 2 && port === '') {
    throw new PolicyError('invalid_network_pattern', `${label}: an explicit port cannot be empty`);
  }
  if (port && !/^\d+$/u.test(port)) {
    throw new PolicyError('invalid_network_pattern', `${label}: wildcard or invalid ports are forbidden`);
  }
  return { hostname, port: canonicalizePort(port, label) };
}

function canonicalizePort(port: string, label: string): string {
  if (port === '') return '';
  const numericPort = Number(port);
  if (!Number.isSafeInteger(numericPort) || numericPort < 0 || numericPort > 65_535) {
    throw new PolicyError('invalid_network_pattern', `${label}: port must be between 0 and 65535`);
  }
  return String(numericPort);
}

function normalizeHostname(hostname: string, label: string): string {
  return normalizeHostnameValue(hostname, label, 'invalid_network_pattern');
}

function normalizeHostnameValue(
  hostname: string,
  label: string,
  code: 'invalid_network_pattern' | 'invalid_url'
): string {
  if (hostname.includes('%')) {
    throw new PolicyError(code, `${label}: percent-encoded hostnames are forbidden`);
  }
  if (hostname.startsWith('[')) {
    if (!hostname.endsWith(']') || isIP(hostname.slice(1, -1)) !== 6) {
      throw new PolicyError(code, `${label}: invalid IPv6 literal`);
    }
    try {
      return new URL(`https://${hostname}/`).hostname.toLowerCase();
    } catch {
      throw new PolicyError(code, `${label}: invalid IPv6 literal`);
    }
  }
  const lexical = hostname.endsWith('.') ? hostname.slice(0, -1) : hostname;
  if (lexical.length === 0 || lexical.split('.').some((part) => part.length === 0)) {
    throw new PolicyError(code, `${label}: DNS labels must be non-empty`);
  }
  const ascii = domainToASCII(lexical).toLowerCase();
  if (
    ascii.length === 0 ||
    ascii.length > 253 ||
    ascii.split('.').some(
      (part) =>
        part.length > 63 ||
        !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(part)
    ) ||
    (isIP(ascii) === 4 && isIP(lexical) !== 4)
  ) {
    throw new PolicyError(code, `${label}: invalid or non-canonical DNS hostname`);
  }
  return ascii;
}

function candidateAuthorityHostname(authority: string): string {
  if (authority.startsWith('[')) {
    const end = authority.indexOf(']');
    if (end < 0) throw new PolicyError('invalid_url', 'URL contains a malformed IPv6 literal');
    const rest = authority.slice(end + 1);
    if (rest && !/^:\d+$/u.test(rest)) {
      throw new PolicyError('invalid_url', 'URL contains an invalid port');
    }
    return authority.slice(0, end + 1);
  }
  const pieces = authority.split(':');
  if (pieces.length > 2) {
    throw new PolicyError('invalid_url', 'IPv6 URL literals must use brackets');
  }
  return pieces[0] ?? '';
}

function normalizePort(scheme: ParsedNetworkPattern['scheme'], port: string): string {
  const defaultPort = scheme === 'http' || scheme === 'ws' ? '80' : '443';
  return port === defaultPort ? '' : port;
}

export function validateStringPattern(pattern: StringPattern, label: string): void {
  if (pattern.value.length === 0 || pattern.value.includes('\0')) {
    throw new PolicyError('invalid_string_pattern', `${label}: pattern must be non-empty and contain no NUL`);
  }
  if (pattern.type === 'glob') validateEnvironmentPattern(pattern.value, label);
  if (pattern.type !== 'literal') {
    const compiled = compileStringPattern(pattern, label);
    if (canMatchEmptySpan(compiled)) {
      throw new PolicyError(
        'invalid_string_pattern',
        `${label}: string patterns must not match the empty string`
      );
    }
  }
}

function canMatchEmptySpan(compiled: RE2JS): boolean {
  // RE2 has six zero-width assertions: text/line start and end plus word and
  // non-word boundaries. These probes cover every surrounding context for
  // those assertions while also exercising nullable consuming expressions.
  for (const probe of ['', 'a', ' ', '\n', 'aa', 'a ', ' a', '  ', 'a\n', '\na', '\n\n']) {
    const matcher = compiled.matcher(probe);
    while (matcher.find()) {
      if (matcher.start() === matcher.end()) return true;
    }
  }
  return false;
}

export function testStringPattern(input: string, pattern: StringPattern): boolean {
  return compileStringPattern(pattern).test(input);
}

export function replaceStringPattern(input: string, pattern: StringPattern, replacement: string): string {
  const matcher = compileStringPattern(pattern).matcher(input);
  const chunks: string[] = [];
  let cursor = 0;
  let outputBytes = 0;
  let replacements = 0;
  const append = (value: string): void => {
    outputBytes += Buffer.byteLength(value);
    if (outputBytes > MAX_STRING_OUTPUT_BYTES) {
      throw new PolicyError(
        'string_output_too_large',
        `redacted string exceeds ${MAX_STRING_OUTPUT_BYTES} bytes`
      );
    }
    chunks.push(value);
  };
  while (matcher.find()) {
    replacements += 1;
    if (replacements > MAX_STRING_REPLACEMENTS) {
      throw new PolicyError(
        'string_replacement_limit',
        `redaction exceeds ${MAX_STRING_REPLACEMENTS} replacements`
      );
    }
    append(input.slice(cursor, matcher.start()));
    append(replacement);
    cursor = matcher.end();
  }
  if (replacements === 0) return input;
  append(input.slice(cursor));
  return chunks.join('');
}

function compileStringPattern(pattern: StringPattern, label = 'string pattern'): RE2JS {
  const cached = STRING_PATTERN_CACHE.get(pattern);
  if (cached) return cached;
  const compiled = pattern.type === 'regex'
    ? compileRegex(pattern, label)
    : compileRegex(
        {
          type: 'regex',
          value: pattern.type === 'literal' ? escapeRegex(pattern.value) : globToRegex(pattern.value),
          ...(pattern.caseSensitive === undefined
            ? {}
            : { caseSensitive: pattern.caseSensitive })
        },
        label === 'string pattern' ? 'string glob' : label
      );
  STRING_PATTERN_CACHE.set(pattern, compiled);
  return compiled;
}

function compileRegex(pattern: StringPattern, label: string): RE2JS {
  let flags = 0;
  if (pattern.caseSensitive === false) flags |= RE2JS.CASE_INSENSITIVE;
  try {
    return RE2JS.compile(pattern.value, flags);
  } catch {
    throw new PolicyError('invalid_string_pattern', `${label}: invalid RE2 pattern`);
  }
}

function globToRegex(glob: string): string {
  let output = '';
  for (let index = 0; index < glob.length; index += 1) {
    const character = glob[index] ?? '';
    if (character === '*') output += '[\\s\\S]*';
    else if (character === '?') output += '[\\s\\S]';
    else if (character === '[') {
      const end = glob.indexOf(']', index + 1);
      if (end === -1) output += '\\[';
      else {
        const content = glob.slice(index + 1, end);
        output += content.startsWith('!') ? `[^${content.slice(1)}]` : `[${content}]`;
        index = end;
      }
    } else output += escapeRegex(character);
  }
  return output;
}

function escapeRegex(value: string): string {
  return value.replace(/[\\^$.*+?()[\]{}|]/gu, '\\$&');
}

function asciiFold(value: string): string {
  return value.replace(/[A-Z]/gu, (character) => character.toLowerCase());
}

function validateCharacterClasses(pattern: string, label: string): void {
  for (let index = 0; index < pattern.length; index += 1) {
    if (pattern[index] !== '[') continue;
    const end = pattern.indexOf(']', index + 1);
    if (end < 0) {
      throw new PolicyError('invalid_pattern', `${label}: unterminated character class`);
    }
    let content = pattern.slice(index + 1, end);
    if (content.startsWith('!')) content = content.slice(1);
    if (content.length === 0 || content.startsWith('^')) {
      throw new PolicyError('invalid_pattern', `${label}: invalid character class`);
    }
    if (
      [...content].some((character) => {
        const codePoint = character.codePointAt(0) ?? 0;
        return (
          codePoint < 0x20 ||
          codePoint > 0x7e ||
          character === '[' ||
          character === ']' ||
          character === '/' ||
          character === '\\'
        );
      })
    ) {
      throw new PolicyError(
        'invalid_pattern',
        `${label}: character classes are limited to printable ASCII without separators`
      );
    }
    for (let offset = 1; offset < content.length - 1; offset += 1) {
      if (content[offset] !== '-') continue;
      if ((content.codePointAt(offset - 1) ?? 0) > (content.codePointAt(offset + 1) ?? 0)) {
        throw new PolicyError('invalid_pattern', `${label}: descending character-class range`);
      }
    }
    index = end;
  }
}

function normalizePercentEncoding(value: string, code: string, label: string): string {
  let output = '';
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index] ?? '';
    if (character !== '%') {
      output += character;
      continue;
    }
    const hex = value.slice(index + 1, index + 3);
    if (!/^[0-9a-f]{2}$/iu.test(hex)) {
      throw new PolicyError(code, `${label}: malformed percent encoding`);
    }
    output += `%${hex.toUpperCase()}`;
    index += 2;
  }
  return output;
}

function rejectEncodedSeparators(value: string, code: string, label: string): void {
  if (/%(?:00|2F|5C)/u.test(value)) {
    throw new PolicyError(code, `${label}: percent-encoded NUL or path separators are forbidden`);
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
