import { PolicyEngine } from '../engine.js';
import { PolicyError } from '../errors.js';
import { collectEnvironmentReferences, collectNamedStrings } from './hook-input.js';
import path from 'node:path';
import type { Decision, EnforcementError, FileOperation, LoadedPolicy } from '../types.js';

interface GeminiHookInput {
  cwd?: string;
  policyRoot?: string;
  hook_event_name?: string;
  tool_name?: string;
  tool_input?: unknown;
}

export interface GeminiHookResult {
  denied: boolean;
  decisions: Decision[];
  errors: EnforcementError[];
  response: { decision: 'allow' | 'deny'; reason?: string; systemMessage?: string };
}

export function evaluateGeminiBeforeTool(
  policy: LoadedPolicy,
  input: GeminiHookInput
): GeminiHookResult {
  const engine = new PolicyEngine(policy);
  const decisions: Decision[] = [];
  const errors: EnforcementError[] = [];
  const serialized = JSON.stringify(input.tool_input ?? {});
  decisions.push(engine.decideString(serialized, 'tool_input'));

  const operation = toolOperation(input.tool_name);
  for (const candidate of collectNamedStrings(input.tool_input, /(^|_)(file_?)?paths?$/iu)) {
    try {
      decisions.push(
        engine.decideFile(
          resolveToolPath(candidate, input.cwd ?? input.policyRoot ?? policy.root),
          operation,
          input.policyRoot ?? policy.root
        )
      );
    } catch (error) {
      errors.push(enforcementError(policy, 'file', error));
    }
  }
  const networkCandidates = collectNamedStrings(input.tool_input, /(^|_)(urls?|uris?|http_urls?)$/iu);
  if (networkCandidates.length > 0) decisions.push(engine.decideString(serialized, 'network_request'));
  for (const candidate of networkCandidates) {
    try {
      decisions.push(engine.decideNetwork(candidate));
    } catch (error) {
      errors.push(enforcementError(policy, 'network', error));
    }
  }
  const command = extractCommand(input.tool_input);
  if (command) {
    for (const variable of collectEnvironmentReferences(command)) {
      decisions.push(engine.decideEnvironment(variable));
    }
  }

  const blocking = decisions.find((decision) =>
    ['deny', 'drop', 'redact'].includes(decision.effect)
  );
  const failure = errors[0];
  if (!blocking && !failure) {
    return { denied: false, decisions, errors, response: { decision: 'allow' } };
  }
  const reason = blockingReason(blocking, failure);
  return {
    denied: true,
    decisions,
    errors,
    response: {
      decision: 'deny',
      reason,
      systemMessage: 'aiignore policy blocked this tool call.'
    }
  };
}

function resolveToolPath(candidate: string, workingDirectory: string): string {
  const portable = candidate.replace(/\\/gu, '/');
  return path.isAbsolute(portable) ? portable : path.resolve(workingDirectory, portable);
}

function extractCommand(value: unknown): string | null {
  if (!value || typeof value !== 'object') return null;
  const record = value as Record<string, unknown>;
  const command = record['command'] ?? record['cmd'];
  return typeof command === 'string' ? command : null;
}

function toolOperation(toolName: string | undefined): FileOperation {
  if (toolName && /copy|create|delete|edit|mkdir|move|remove|rename|replace|touch|write/iu.test(toolName)) return 'write';
  if (toolName && /shell|exec|run_/iu.test(toolName)) return 'execute';
  if (toolName && /glob|grep|list|search/iu.test(toolName)) return 'discover';
  return 'read';
}

function enforcementError(
  policy: LoadedPolicy,
  resource: 'file' | 'network',
  error: unknown
): EnforcementError {
  return {
    error: error instanceof PolicyError ? error.code : 'unexpected_error',
    resource,
    message: `${resource} candidate could not be safely evaluated`,
    policyDigest: policy.digest
  };
}

function blockingReason(
  decision: Decision | undefined,
  failure: EnforcementError | undefined
): string {
  if (failure) {
    return `aiignore enforcement failed closed for ${failure.resource} (${failure.error})`;
  }
  if (decision) {
    return `aiignore policy blocked ${decision.resource} via ${decision.ruleId ?? 'default policy'} (${decision.reason})`;
  }
  throw new Error('blocking reason requires a decision or enforcement error');
}
