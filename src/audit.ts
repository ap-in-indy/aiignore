import { PolicyError } from './errors.js';
import { validateAuditEventSchema } from './schema.js';
import type { AuditEvent, Decision } from './types.js';

export function createAuditEvent(decision: Decision): AuditEvent {
  if (decision.effect !== 'audit' || decision.ruleId === null) {
    throw new PolicyError(
      'invalid_audit_decision',
      'an audit event requires an audit decision selected by a rule'
    );
  }
  const event: AuditEvent = {
    event: 'aiignore.audit',
    formatVersion: '0.1',
    resource: decision.resource,
    ruleId: decision.ruleId,
    policyDigest: decision.policyDigest
  };
  if (validateAuditEventSchema(event).length > 0) {
    throw new PolicyError('invalid_audit_decision', 'audit decision metadata is not portable');
  }
  return event;
}
