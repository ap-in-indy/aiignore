export const FILE_OPERATIONS = Object.freeze(
  ['discover', 'index', 'read', 'write', 'execute'] as const
);
export type FileOperation = (typeof FILE_OPERATIONS)[number];

export const STRING_SCOPES = Object.freeze([
  'user_prompt',
  'model_input',
  'model_output',
  'tool_input',
  'tool_output',
  'file_read',
  'file_write',
  'environment_value',
  'network_request',
  'network_response',
  'log'
] as const);
export type StringScope = (typeof STRING_SCOPES)[number];

export const DEFAULT_EFFECTS = Object.freeze(['allow', 'deny'] as const);
export const FILE_EFFECTS = Object.freeze(['allow', 'deny', 'audit', 'read-only'] as const);
export const ENVIRONMENT_EFFECTS = Object.freeze(
  ['allow', 'drop', 'redact', 'deny', 'audit'] as const
);
export const NETWORK_EFFECTS = Object.freeze(['allow', 'deny', 'audit'] as const);
export const STRING_EFFECTS = Object.freeze(['allow', 'deny', 'redact', 'audit'] as const);
export const STRING_PATTERN_TYPES = Object.freeze(['literal', 'glob', 'regex'] as const);
export const RESOURCES = Object.freeze(['file', 'environment', 'network', 'string'] as const);
export const DECISION_EFFECTS = Object.freeze(
  ['allow', 'deny', 'drop', 'redact', 'audit'] as const
);

export type DefaultEffect = (typeof DEFAULT_EFFECTS)[number];
export type FileEffect = (typeof FILE_EFFECTS)[number];
export type EnvironmentEffect = (typeof ENVIRONMENT_EFFECTS)[number];
export type NetworkEffect = (typeof NETWORK_EFFECTS)[number];
export type StringEffect = (typeof STRING_EFFECTS)[number];

export interface Metadata {
  readonly name?: string;
  readonly description?: string;
}

export interface Defaults {
  readonly files?: DefaultEffect;
  readonly environment?: DefaultEffect;
  readonly network?: DefaultEffect;
  readonly strings?: DefaultEffect;
}

export interface BaseRule {
  readonly id: string;
  readonly priority?: number;
}

export interface FileRule extends BaseRule {
  readonly effect: FileEffect;
  readonly operations?: readonly FileOperation[];
  readonly paths: readonly string[];
  readonly except?: readonly string[];
}

export interface EnvironmentRule extends BaseRule {
  readonly effect: EnvironmentEffect;
  readonly names: readonly string[];
  readonly except?: readonly string[];
  readonly replacement?: string;
}

export interface NetworkRule extends BaseRule {
  readonly effect: NetworkEffect;
  readonly urls: readonly string[];
  readonly except?: readonly string[];
}

export interface StringPattern {
  readonly type: (typeof STRING_PATTERN_TYPES)[number];
  readonly value: string;
  readonly caseSensitive?: boolean;
}

export interface StringRule extends BaseRule {
  readonly effect: StringEffect;
  readonly scopes?: readonly StringScope[];
  readonly patterns: readonly StringPattern[];
  readonly except?: readonly StringPattern[];
  readonly replacement?: string;
}

export interface Rules {
  readonly files?: readonly FileRule[];
  readonly environment?: readonly EnvironmentRule[];
  readonly network?: readonly NetworkRule[];
  readonly strings?: readonly StringRule[];
}

export interface PolicyDocument {
  readonly aiignore: '0.1';
  readonly metadata?: Metadata;
  readonly defaults?: Defaults;
  readonly rules?: Rules;
}

export interface LoadedPolicy {
  readonly document: PolicyDocument;
  readonly digest: string;
  readonly source: string;
  readonly root: string;
}

export type DecisionEffect = (typeof DECISION_EFFECTS)[number];
export type Resource = (typeof RESOURCES)[number];

export interface Decision {
  resource: Resource;
  effect: DecisionEffect;
  ruleId: string | null;
  matched: string | null;
  reason: string;
  policyDigest: string;
  output?: string;
  appliedRuleIds?: string[];
}

export interface AuditEvent {
  readonly event: 'aiignore.audit';
  readonly formatVersion: '0.1';
  readonly resource: Resource;
  readonly ruleId: string;
  readonly policyDigest: string;
}

export interface EnforcementError {
  readonly error: string;
  readonly resource: 'file' | 'network';
  readonly message: string;
  readonly policyDigest: string;
}

export interface ResourceCounts {
  readonly files: number;
  readonly environment: number;
  readonly network: number;
  readonly strings: number;
}

export interface ReadinessAdapterSummary {
  readonly compilationExact: boolean;
  readonly errorGaps: number;
  readonly warningGaps: number;
}

export type ReadinessFindingId =
  | 'deployment-not-established'
  | 'repository-policy-not-administrator-control'
  | 'network-default-allow'
  | 'no-file-deny-rules'
  | 'no-environment-filter-rules'
  | 'no-string-boundary-rules'
  | 'codex-compilation-partial'
  | 'gemini-compilation-partial';

export interface ReadinessFinding {
  readonly id: ReadinessFindingId;
  readonly severity: 'info' | 'warning';
  readonly message: string;
}

export interface ReadinessReport {
  readonly formatVersion: '0.1';
  readonly policyDigest: string;
  readonly policyValid: true;
  readonly deploymentEnforcement: 'not-established';
  readonly defaults: Readonly<Record<keyof ResourceCounts, DefaultEffect>>;
  readonly ruleCounts: ResourceCounts;
  readonly controlCounts: {
    readonly fileDeny: number;
    readonly environmentFilter: number;
    readonly networkDeny: number;
    readonly networkAllow: number;
    readonly stringBoundary: number;
  };
  readonly adapters: {
    readonly codex: ReadinessAdapterSummary;
    readonly gemini: ReadinessAdapterSummary;
  };
  readonly findings: readonly ReadinessFinding[];
}

export type ImplementationClassification = 'reference' | 'derived' | 'independent';

export interface ImplementationConformanceSuite {
  readonly kind: 'parser' | 'decision';
  readonly revision: string;
  readonly vectorsUri: string;
  readonly vectorsSha256: string;
  readonly policySha256?: string;
  readonly total: number;
  readonly passed: number;
  readonly failedCaseIds: readonly string[];
  readonly conformant: boolean;
}

export interface ImplementationConformanceReport {
  readonly reportVersion: '0.1';
  readonly reportType: 'implementation';
  readonly status: 'provisional' | 'verified' | 'withdrawn';
  readonly date: string;
  readonly specification: '0.1';
  readonly conformanceBundle: {
    readonly formatVersion: '0.1';
    readonly release: string;
    readonly uri: string;
    readonly sha256: string;
  };
  readonly implementation: {
    readonly name: string;
    readonly version: string;
    readonly language: string;
    readonly classification: ImplementationClassification;
    readonly sourceUri: string;
    readonly sourceRevision: string;
    readonly sourceSha256: string;
    readonly sourceTreeDirty: boolean;
  };
  readonly runner: {
    readonly name: string;
    readonly version: string;
    readonly sha256: string;
  };
  readonly suites: readonly ImplementationConformanceSuite[];
  readonly summary: {
    readonly total: number;
    readonly passed: number;
    readonly failed: number;
    readonly conformant: boolean;
  };
  readonly limitations: readonly string[];
  readonly evidence?: readonly {
    readonly type: 'log' | 'attestation' | 'signature' | 'artifact' | 'other';
    readonly uri: string;
    readonly sha256: string;
  }[];
  readonly verification?: {
    readonly method: 'aiignore-ed25519-v0.1';
    readonly identity: string;
    readonly issuer?: string;
    readonly envelopeUri: string;
    readonly publicKeySha256: string;
  };
  readonly withdrawalReason?: string;
}

export interface EnvironmentFilterResult {
  environment: Record<string, string>;
  decisions: Record<string, Decision>;
  valueDecisions: Record<string, Decision>;
  denied: string[];
}

export interface CodexCompilation {
  format: 'codex-permission-profile-v1';
  policyDigest: string;
  minimumCodexVersion: string;
  toml: string;
  gaps: CompilationGap[];
  exact: boolean;
}

export interface GeminiCompilation {
  format: 'gemini-cli-adapter-v1';
  policyDigest: string;
  ignoreFileName: string;
  ignoreFile: string;
  settings: {
    context: {
      fileFiltering: {
        customIgnoreFilePaths: string[];
      };
    };
    security: {
      environmentVariableRedaction: {
        enabled: boolean;
        allowed: string[];
        blocked: string[];
      };
    };
  };
  gaps: CompilationGap[];
  exact: boolean;
}

export interface CompilationGap {
  resource: Resource;
  ruleId: string | null;
  severity: 'warning' | 'error';
  message: string;
}
