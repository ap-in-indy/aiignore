import {
  canonicalizeCandidatePath,
  canonicalizeUrl,
  matchEnvironmentPattern,
  matchFilePattern,
  matchNetworkPattern,
  parseNetworkPattern,
  replaceStringPattern,
  testStringPattern,
  validateEnvironmentName
} from './patterns.js';
import { PolicyError } from './errors.js';
import { FILE_OPERATIONS, STRING_SCOPES } from './types.js';
import type {
  Decision,
  DecisionEffect,
  EnvironmentFilterResult,
  EnvironmentRule,
  DefaultEffect,
  FileEffect,
  FileOperation,
  FileRule,
  LoadedPolicy,
  NetworkRule,
  StringRule,
  StringScope
} from './types.js';

interface Match<T> {
  rule: T;
  matched: string;
  index: number;
}

export const MAX_STRING_WORK_BYTES = 128 * 1024 * 1024;
export const MAX_RESOURCE_CANDIDATE_BYTES = 1024 * 1024;
export const MAX_RESOURCE_WORK_BYTES = 1024 * 1024;
const FILE_OPERATION_SET = new Set<string>(FILE_OPERATIONS);
const STRING_SCOPE_SET = new Set<string>(STRING_SCOPES);

export class PolicyEngine {
  readonly policy: LoadedPolicy;
  private readonly networkPatterns = new Map<string, ReturnType<typeof parseNetworkPattern>>();

  constructor(policy: LoadedPolicy) {
    this.policy = Object.freeze({
      document: policy.document,
      digest: policy.digest,
      source: policy.source,
      root: policy.root
    });
    for (const rule of this.policy.document.rules?.network ?? []) {
      for (const pattern of [...rule.urls, ...(rule.except ?? [])]) {
        if (!this.networkPatterns.has(pattern)) {
          this.networkPatterns.set(pattern, parseNetworkPattern(pattern, `${rule.id}.urls`));
        }
      }
    }
  }

  decideFile(
    candidate: string,
    operation: FileOperation,
    root = this.policy.root,
    caseInsensitive = process.platform === 'win32'
  ): Decision {
    if (!FILE_OPERATION_SET.has(operation)) {
      throw new PolicyError('invalid_file_operation', 'file operation is not supported');
    }
    enforceResourceCandidateLimit(candidate);
    const canonical = canonicalizeCandidatePath(candidate, root);
    const candidateBytes = Buffer.byteLength(canonical);
    let workBytes = 0;
    const matchesPattern = (pattern: string): boolean => {
      workBytes = consumeResourceWork(workBytes, candidateBytes);
      return matchFilePattern(canonical, pattern, caseInsensitive);
    };
    const matches: Match<FileRule>[] = [];
    for (const [index, rule] of (this.policy.document.rules?.files ?? []).entries()) {
      if (!(rule.operations ?? FILE_OPERATIONS).includes(operation)) continue;
      if (
        (rule.except ?? []).some(matchesPattern)
      ) {
        continue;
      }
      const matched = rule.paths.find(matchesPattern);
      if (matched) matches.push({ rule, matched, index });
    }
    const selected = select(matches);
    if (!selected) return this.defaultDecision('file', this.policy.document.defaults?.files);
    return this.decision(
      'file',
      resolveFileEffect(selected.rule.effect, operation),
      selected.rule.id,
      selected.matched
    );
  }

  decideEnvironment(name: string, caseInsensitive = process.platform === 'win32'): Decision {
    enforceResourceCandidateLimit(name);
    validateEnvironmentName(name);
    const candidateBytes = Buffer.byteLength(name);
    let workBytes = 0;
    const matchesPattern = (pattern: string): boolean => {
      workBytes = consumeResourceWork(workBytes, candidateBytes);
      return matchEnvironmentPattern(name, pattern, caseInsensitive);
    };
    const matches: Match<EnvironmentRule>[] = [];
    for (const [index, rule] of (this.policy.document.rules?.environment ?? []).entries()) {
      if (
        (rule.except ?? []).some(matchesPattern)
      ) {
        continue;
      }
      const matched = rule.names.find(matchesPattern);
      if (matched) matches.push({ rule, matched, index });
    }
    const selected = select(matches);
    if (!selected) return this.defaultDecision('environment', this.policy.document.defaults?.environment);
    const decision = this.decision(
      'environment',
      selected.rule.effect,
      selected.rule.id,
      selected.matched
    );
    if (selected.rule.effect === 'redact') decision.output = selected.rule.replacement ?? '[REDACTED]';
    return decision;
  }

  filterEnvironment(environment: Record<string, string | undefined>): EnvironmentFilterResult {
    const output: Record<string, string> = Object.create(null) as Record<string, string>;
    const decisions: Record<string, Decision> = Object.create(null) as Record<string, Decision>;
    const valueDecisions: Record<string, Decision> = Object.create(null) as Record<string, Decision>;
    const denied: string[] = [];
    for (const [name, value] of Object.entries(environment)) {
      if (value === undefined) continue;
      const nameDecision = this.decideEnvironment(name);
      decisions[name] = nameDecision;
      if (nameDecision.effect === 'drop') continue;
      if (nameDecision.effect === 'deny') {
        denied.push(name);
        continue;
      }
      let nextValue = nameDecision.effect === 'redact' ? (nameDecision.output ?? '[REDACTED]') : value;
      const stringDecision = this.decideString(nextValue, 'environment_value');
      valueDecisions[name] = stringDecision;
      if (stringDecision.effect === 'deny') {
        denied.push(name);
        continue;
      }
      if (stringDecision.effect === 'redact') nextValue = stringDecision.output ?? nextValue;
      output[name] = nextValue;
    }
    return { environment: output, decisions, valueDecisions, denied };
  }

  decideNetwork(candidate: string): Decision {
    enforceResourceCandidateLimit(candidate);
    const canonical = canonicalizeUrl(candidate);
    const candidateBytes = Buffer.byteLength(candidate);
    let workBytes = 0;
    const matchesPattern = (pattern: string): boolean => {
      workBytes = consumeResourceWork(workBytes, candidateBytes);
      return matchNetworkPattern(canonical, this.networkPattern(pattern));
    };
    const matches: Match<NetworkRule>[] = [];
    for (const [index, rule] of (this.policy.document.rules?.network ?? []).entries()) {
      if (
        (rule.except ?? []).some(matchesPattern)
      ) {
        continue;
      }
      const matched = rule.urls.find(matchesPattern);
      if (matched) matches.push({ rule, matched, index });
    }
    const selected = select(matches);
    if (!selected) return this.defaultDecision('network', this.policy.document.defaults?.network);
    return this.decision('network', selected.rule.effect, selected.rule.id, selected.matched);
  }

  decideString(input: string, scope: StringScope): Decision {
    if (!STRING_SCOPE_SET.has(scope)) {
      throw new PolicyError('invalid_string_scope', 'string scope is not supported');
    }
    const matches: Match<StringRule>[] = [];
    let workBytes = 0;
    const testPattern = (value: string, pattern: StringRule['patterns'][number]): boolean => {
      workBytes = consumeStringWork(workBytes, value);
      return testStringPattern(value, pattern);
    };
    for (const [index, rule] of (this.policy.document.rules?.strings ?? []).entries()) {
      if (!(rule.scopes ?? STRING_SCOPES).includes(scope)) continue;
      if ((rule.except ?? []).some((pattern) => testPattern(input, pattern))) continue;
      const matchedPattern = rule.patterns.find((pattern) => testPattern(input, pattern));
      if (matchedPattern) {
        // String patterns may themselves contain sensitive literals. Decisions
        // identify only the matcher type and never echo the configured value.
        matches.push({ rule, matched: matchedPattern.type, index });
      }
    }
    const selected = select(matches);
    if (!selected) return this.defaultDecision('string', this.policy.document.defaults?.strings);
    const decision = this.decision('string', selected.rule.effect, selected.rule.id, selected.matched);
    if (selected.rule.effect === 'redact') {
      const redactions = matches
        .filter((match) => match.rule.effect === 'redact')
        .sort(compareMatches);
      decision.output = redactions.reduce((value, match) => {
        const replacement = match.rule.replacement ?? `[REDACTED:${match.rule.id}]`;
        return match.rule.patterns.reduce(
          (current, pattern) => {
            workBytes = consumeStringWork(workBytes, current);
            return replaceStringPattern(current, pattern, replacement);
          },
          value
        );
      }, input);
      decision.appliedRuleIds = redactions.map((match) => match.rule.id);
    }
    return decision;
  }

  private defaultDecision(
    resource: Decision['resource'],
    effect: DefaultEffect = 'allow'
  ): Decision {
    return {
      resource,
      effect,
      ruleId: null,
      matched: null,
      reason: `resource default is ${effect}`,
      policyDigest: this.policy.digest
    };
  }

  private decision(
    resource: Decision['resource'],
    effect: DecisionEffect,
    ruleId: string,
    matched: string
  ): Decision {
    return {
      resource,
      effect,
      ruleId,
      matched,
      reason: `matched rule ${ruleId}`,
      policyDigest: this.policy.digest
    };
  }

  private networkPattern(pattern: string): ReturnType<typeof parseNetworkPattern> {
    const parsed = this.networkPatterns.get(pattern);
    if (!parsed) throw new Error('validated network pattern cache is incomplete');
    return parsed;
  }
}

function enforceResourceCandidateLimit(candidate: string): void {
  if (Buffer.byteLength(candidate) > MAX_RESOURCE_CANDIDATE_BYTES) {
    throw new PolicyError(
      'candidate_too_large',
      `candidate exceeds ${MAX_RESOURCE_CANDIDATE_BYTES} bytes`
    );
  }
}

function consumeResourceWork(current: number, candidateBytes: number): number {
  if (current > MAX_RESOURCE_WORK_BYTES - candidateBytes) {
    throw new PolicyError(
      'resource_work_limit',
      `cumulative resource matcher work exceeds ${MAX_RESOURCE_WORK_BYTES} bytes`
    );
  }
  return current + candidateBytes;
}

function consumeStringWork(current: number, value: string): number {
  const next = current + Math.max(1, Buffer.byteLength(value));
  if (next > MAX_STRING_WORK_BYTES) {
    throw new PolicyError(
      'string_work_limit',
      `string matching exceeds ${MAX_STRING_WORK_BYTES} cumulative input bytes`
    );
  }
  return next;
}

function select<T extends { priority?: number }>(matches: Match<T>[]): Match<T> | undefined {
  let selected: Match<T> | undefined;
  for (const match of matches) {
    if (!selected || compareMatches(match, selected) < 0) selected = match;
  }
  return selected;
}

function compareMatches<T extends { priority?: number }>(left: Match<T>, right: Match<T>): number {
  const priority = (right.rule.priority ?? 0) - (left.rule.priority ?? 0);
  return priority === 0 ? right.index - left.index : priority;
}

function resolveFileEffect(effect: FileEffect, operation: FileOperation): DecisionEffect {
  if (effect !== 'read-only') return effect;
  return operation === 'write' || operation === 'execute' ? 'deny' : 'allow';
}
