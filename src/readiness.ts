import { compileCodexPermissionProfile } from './adapters/codex.js';
import { compileGeminiConfiguration } from './adapters/gemini.js';
import { PolicyError } from './errors.js';
import { validateReadinessReportSchema } from './schema.js';
import type {
  CompilationGap,
  DefaultEffect,
  LoadedPolicy,
  ReadinessAdapterSummary,
  ReadinessFinding,
  ReadinessReport,
  ResourceCounts
} from './types.js';

export function assessReadiness(policy: LoadedPolicy): ReadinessReport {
  const files = policy.document.rules?.files ?? [];
  const environment = policy.document.rules?.environment ?? [];
  const network = policy.document.rules?.network ?? [];
  const strings = policy.document.rules?.strings ?? [];
  const defaults = {
    files: policy.document.defaults?.files ?? 'allow',
    environment: policy.document.defaults?.environment ?? 'allow',
    network: policy.document.defaults?.network ?? 'allow',
    strings: policy.document.defaults?.strings ?? 'allow'
  } satisfies Record<keyof ResourceCounts, DefaultEffect>;
  const ruleCounts = {
    files: files.length,
    environment: environment.length,
    network: network.length,
    strings: strings.length
  } satisfies ResourceCounts;
  const controlCounts = {
    fileDeny: files.filter((rule) => rule.effect === 'deny').length,
    environmentFilter: environment.filter((rule) =>
      ['drop', 'redact', 'deny'].includes(rule.effect)
    ).length,
    networkDeny: network.filter((rule) => rule.effect === 'deny').length,
    networkAllow: network.filter((rule) => rule.effect === 'allow').length,
    stringBoundary: strings.filter((rule) => ['deny', 'redact'].includes(rule.effect)).length
  };
  const codex = summarizeGaps(compileCodexPermissionProfile(policy).gaps);
  const gemini = summarizeGaps(compileGeminiConfiguration(policy).gaps);
  const findings: ReadinessFinding[] = [
    {
      id: 'deployment-not-established',
      severity: 'warning',
      message:
        'Policy validity and adapter compilation do not prove that a harness or sandbox mediates every access path.'
    },
    {
      id: 'repository-policy-not-administrator-control',
      severity: 'info',
      message:
        'A repository-controlled policy is developer intent, not a non-bypassable organization control.'
    }
  ];
  if (defaults.network === 'allow') {
    findings.push({
      id: 'network-default-allow',
      severity: 'warning',
      message: 'Unmatched network destinations are allowed by the policy default.'
    });
  }
  if (defaults.files === 'allow' && controlCounts.fileDeny === 0) {
    findings.push({
      id: 'no-file-deny-rules',
      severity: 'warning',
      message: 'The policy has no file deny rule and unmatched files are allowed.'
    });
  }
  if (defaults.environment === 'allow' && controlCounts.environmentFilter === 0) {
    findings.push({
      id: 'no-environment-filter-rules',
      severity: 'warning',
      message: 'The policy does not drop, redact, or deny any environment-variable name.'
    });
  }
  if (defaults.strings === 'allow' && controlCounts.stringBoundary === 0) {
    findings.push({
      id: 'no-string-boundary-rules',
      severity: 'info',
      message: 'The policy has no string deny or redaction rule; string filtering remains optional defense in depth.'
    });
  }
  if (!codex.compilationExact) {
    findings.push({
      id: 'codex-compilation-partial',
      severity: 'warning',
      message: 'The Codex permission-profile translation has semantic gaps; inspect the full compilation report.'
    });
  }
  if (!gemini.compilationExact) {
    findings.push({
      id: 'gemini-compilation-partial',
      severity: 'warning',
      message: 'The Gemini context/settings translation has semantic gaps; inspect the full compilation report.'
    });
  }
  const report: ReadinessReport = {
    formatVersion: '0.1',
    policyDigest: policy.digest,
    policyValid: true,
    deploymentEnforcement: 'not-established',
    defaults,
    ruleCounts,
    controlCounts,
    adapters: { codex, gemini },
    findings
  };
  if (validateReadinessReportSchema(report).length > 0) {
    throw new PolicyError('readiness_schema_validation', 'readiness report is not portable');
  }
  return report;
}

function summarizeGaps(gaps: readonly CompilationGap[]): ReadinessAdapterSummary {
  const errorGaps = gaps.filter((gap) => gap.severity === 'error').length;
  const warningGaps = gaps.length - errorGaps;
  return { compilationExact: gaps.length === 0, errorGaps, warningGaps };
}
