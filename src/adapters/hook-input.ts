import { PolicyError } from '../errors.js';

export const MAX_HOOK_TRAVERSAL_DEPTH = 64;
export const MAX_HOOK_TRAVERSAL_NODES = 4096;
export const MAX_HOOK_CANDIDATES = 128;
export const MAX_HOOK_CANDIDATE_BYTES = 1024 * 1024;

export function collectNamedStrings(value: unknown, keyPattern: RegExp): string[] {
  const output: string[] = [];
  const stack: Array<{ value: unknown; depth: number; collectStrings: boolean }> = [
    { value, depth: 0, collectStrings: false }
  ];
  let nodes = 0;
  let candidateBytes = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) break;
    nodes += 1;
    if (nodes > MAX_HOOK_TRAVERSAL_NODES || current.depth > MAX_HOOK_TRAVERSAL_DEPTH) {
      throw new PolicyError('hook_input_limit', 'hook input traversal limit exceeded');
    }
    if (typeof current.value === 'string' && current.collectStrings) {
      output.push(current.value);
      candidateBytes += Buffer.byteLength(current.value);
      if (output.length > MAX_HOOK_CANDIDATES || candidateBytes > MAX_HOOK_CANDIDATE_BYTES) {
        throw new PolicyError('hook_input_limit', 'hook candidate limit exceeded');
      }
      continue;
    }
    if (Array.isArray(current.value)) {
      for (const child of current.value) {
        stack.push({
          value: child,
          depth: current.depth + 1,
          collectStrings: current.collectStrings
        });
      }
      continue;
    }
    if (!current.value || typeof current.value !== 'object') continue;
    for (const [key, child] of Object.entries(current.value)) {
      stack.push({
        value: child,
        depth: current.depth + 1,
        collectStrings: current.collectStrings || keyPattern.test(key)
      });
    }
  }
  return output;
}

export function collectEnvironmentReferences(command: string): string[] {
  const output: string[] = [];
  for (const match of command.matchAll(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/gu)) {
    const variable = match[1];
    if (!variable) continue;
    output.push(variable);
    if (output.length > MAX_HOOK_CANDIDATES) {
      throw new PolicyError('hook_input_limit', 'hook environment-reference limit exceeded');
    }
  }
  return output;
}
