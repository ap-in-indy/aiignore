/** The normative structured-policy filename for aiignore draft 0.1. */
export const POLICY_FILENAME = '.aiignore.yaml';

/**
 * Existing tools use this exact filename for gitignore-style path exclusions.
 * It is intentionally not parsed as a structured aiignore policy.
 */
export const LEGACY_IGNORE_FILENAME = '.aiignore';

export function isLegacyIgnoreFilename(filename: string): boolean {
  return filename.toLowerCase() === LEGACY_IGNORE_FILENAME;
}

export const SPEC_VERSION = '0.1';
export const PACKAGE_VERSION = '0.1.0-alpha.1';
