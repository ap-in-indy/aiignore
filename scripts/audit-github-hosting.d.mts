export interface HostingAuditOptions {
  policyPath?: string;
  snapshotPath?: string;
  repository?: string;
  json?: boolean;
  validatePolicy?: boolean;
}

export interface HostingAuditFinding {
  path: string;
  expected: unknown;
  actual: unknown;
}

export interface HostingAuditResult {
  valid: boolean;
  repository: string;
  findings: HostingAuditFinding[];
}

export function auditGithubHosting(options?: HostingAuditOptions): HostingAuditResult;
