import { readFileSync } from 'node:fs';
import { Ajv2020, type ErrorObject } from 'ajv/dist/2020.js';
import type {
  AuditEvent,
  Decision,
  ImplementationConformanceReport,
  PolicyDocument,
  ReadinessReport
} from './types.js';

const schemaUrl = new URL('../schema/aiignore.schema.json', import.meta.url);
export const AIIGNORE_SCHEMA = JSON.parse(readFileSync(schemaUrl, 'utf8')) as object;
export const DECISION_SCHEMA = JSON.parse(
  readFileSync(new URL('../schema/decision.schema.json', import.meta.url), 'utf8')
) as object;
export const AUDIT_EVENT_SCHEMA = JSON.parse(
  readFileSync(new URL('../schema/audit-event.schema.json', import.meta.url), 'utf8')
) as object;
export const READINESS_REPORT_SCHEMA = JSON.parse(
  readFileSync(new URL('../schema/readiness-report.schema.json', import.meta.url), 'utf8')
) as object;
export const IMPLEMENTATION_CONFORMANCE_REPORT_SCHEMA = JSON.parse(
  readFileSync(
    new URL('../schema/implementation-conformance-report.schema.json', import.meta.url),
    'utf8'
  )
) as object;

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  validateFormats: false
});
const validate = ajv.compile<PolicyDocument>(AIIGNORE_SCHEMA);
const validateDecision = ajv.compile<Decision>(DECISION_SCHEMA);
const validateAuditEvent = ajv.compile<AuditEvent>(AUDIT_EVENT_SCHEMA);
const validateReadinessReport = ajv.compile<ReadinessReport>(READINESS_REPORT_SCHEMA);
const validateImplementationConformanceReport = ajv.compile<ImplementationConformanceReport>(
  IMPLEMENTATION_CONFORMANCE_REPORT_SCHEMA
);

export function validateSchema(value: unknown): ErrorObject[] {
  return validate(value) ? [] : [...(validate.errors ?? [])];
}

export function validateDecisionSchema(value: unknown): ErrorObject[] {
  return validateDecision(value) ? [] : [...(validateDecision.errors ?? [])];
}

export function validateAuditEventSchema(value: unknown): ErrorObject[] {
  return validateAuditEvent(value) ? [] : [...(validateAuditEvent.errors ?? [])];
}

export function validateReadinessReportSchema(value: unknown): ErrorObject[] {
  return validateReadinessReport(value) ? [] : [...(validateReadinessReport.errors ?? [])];
}

export function validateImplementationConformanceReportSchema(value: unknown): ErrorObject[] {
  return validateImplementationConformanceReport(value)
    ? []
    : [...(validateImplementationConformanceReport.errors ?? [])];
}
