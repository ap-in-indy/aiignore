import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signBytes,
  verify as verifyBytes,
  type KeyObject
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Ajv2020, type ErrorObject } from 'ajv/dist/2020.js';
import { PolicyError } from './errors.js';
import { assertImplementationConformanceReport } from './implementation-conformance.js';
import type { ImplementationConformanceReport } from './types.js';

const reportSchemaUrl = new URL('../schema/conformance-report.schema.json', import.meta.url);
const implementationReportSchemaUrl = new URL(
  '../schema/implementation-conformance-report.schema.json',
  import.meta.url
);
const envelopeSchemaUrl = new URL(
  '../schema/conformance-signature-envelope.schema.json',
  import.meta.url
);
export const CONFORMANCE_REPORT_SCHEMA = JSON.parse(
  readFileSync(reportSchemaUrl, 'utf8')
) as object;
const IMPLEMENTATION_CONFORMANCE_REPORT_SCHEMA = JSON.parse(
  readFileSync(implementationReportSchemaUrl, 'utf8')
) as object;
export const CONFORMANCE_SIGNATURE_ENVELOPE_SCHEMA = JSON.parse(
  readFileSync(envelopeSchemaUrl, 'utf8')
) as object;

export const CONFORMANCE_REPORT_MEDIA_TYPE =
  'application/vnd.aiignore.conformance-report+json;version=0.1';
export const IMPLEMENTATION_CONFORMANCE_REPORT_MEDIA_TYPE =
  'application/vnd.aiignore.implementation-conformance-report+json;version=0.1';
export type ConformanceReportMediaType =
  | typeof CONFORMANCE_REPORT_MEDIA_TYPE
  | typeof IMPLEMENTATION_CONFORMANCE_REPORT_MEDIA_TYPE;
export const MAX_CONFORMANCE_REPORT_BYTES = 4 * 1024 * 1024;
export const MAX_CONFORMANCE_ENVELOPE_BYTES = 64 * 1024;

interface ReportVerification {
  method: 'aiignore-ed25519-v0.1';
  identity: string;
  issuer?: string;
  envelopeUri: string;
  publicKeySha256: string;
}

interface ConformanceReport {
  status: 'provisional' | 'verified' | 'withdrawn';
  sourceTreeDirty?: boolean;
  implementation?: { sourceTreeDirty: boolean; [key: string]: unknown };
  evidence?: unknown[];
  verification?: ReportVerification;
  withdrawalReason?: string;
  [key: string]: unknown;
}

export interface ConformanceSignatureEnvelope {
  formatVersion: '0.1';
  payloadType: ConformanceReportMediaType;
  payloadSha256: string;
  signatureAlgorithm: 'ed25519';
  identity: string;
  issuer?: string;
  publicKey: {
    format: 'spki-pem';
    sha256: string;
    value: string;
  };
  signatureBase64: string;
}

export interface SignConformanceReportOptions {
  identity: string;
  issuer?: string;
  envelopeUri: string;
}

export interface SignedConformanceReport {
  reportBytes: Uint8Array;
  envelopeBytes: Uint8Array;
  reportSha256: string;
  publicKeySha256: string;
  payloadType: ConformanceReportMediaType;
}

export interface VerifyConformanceReportOptions {
  expectedIdentity: string;
  expectedPublicKeySha256: string;
  expectedIssuer?: string;
}

export interface VerifiedConformanceReport {
  verified: true;
  reportSha256: string;
  publicKeySha256: string;
  identity: string;
  issuer: string | null;
  payloadType: ConformanceReportMediaType;
}

const ajv = new Ajv2020({ allErrors: true, strict: true, validateFormats: false });
const validateReport = ajv.compile<ConformanceReport>(CONFORMANCE_REPORT_SCHEMA);
const validateImplementationReport = ajv.compile<ConformanceReport>(
  IMPLEMENTATION_CONFORMANCE_REPORT_SCHEMA
);
const validateEnvelope = ajv.compile<ConformanceSignatureEnvelope>(
  CONFORMANCE_SIGNATURE_ENVELOPE_SCHEMA
);

export function signConformanceReport(
  provisionalReportBytes: Uint8Array,
  privateKeyBytes: Uint8Array | string,
  options: SignConformanceReportOptions
): SignedConformanceReport {
  const parsed = parseReport(provisionalReportBytes);
  const { report, payloadType } = parsed;
  if (report.status !== 'provisional') {
    throw new PolicyError('report_not_provisional', 'only a provisional report can be signed');
  }
  if (reportIsDirty(report, payloadType)) {
    throw new PolicyError('report_source_dirty', 'a report from a dirty source tree cannot be verified');
  }
  if (!report.evidence || report.evidence.length === 0) {
    throw new PolicyError(
      'report_evidence_missing',
      'a verified report requires content-addressed evidence'
    );
  }
  validateIdentity(options.identity, 'identity');
  if (options.issuer !== undefined) validateIdentity(options.issuer, 'issuer');
  if (!/^https:\/\/[^\s]+$/u.test(options.envelopeUri) || options.envelopeUri.length > 2048) {
    throw new PolicyError('invalid_envelope_uri', 'envelope URI must be a bounded HTTPS URI');
  }

  const privateKey = parseEd25519PrivateKey(privateKeyBytes);
  const publicKey = createPublicKey(privateKey.export({ type: 'pkcs8', format: 'pem' }));
  const publicKeyDer = exportPublicKeyDer(publicKey);
  const publicKeySha256 = sha256(publicKeyDer);
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const verification: ReportVerification = {
    method: 'aiignore-ed25519-v0.1',
    identity: options.identity,
    ...(options.issuer === undefined ? {} : { issuer: options.issuer }),
    envelopeUri: options.envelopeUri,
    publicKeySha256
  };
  const verifiedReport: ConformanceReport = {
    ...report,
    status: 'verified',
    verification
  };
  delete verifiedReport.withdrawalReason;
  assertValidReport(verifiedReport, payloadType);
  const reportBytes = Buffer.from(`${JSON.stringify(verifiedReport, null, 2)}\n`);
  const reportSha256 = sha256(reportBytes);
  const signature = signBytes(null, signatureMessage(payloadType, reportSha256), privateKey);
  const envelope: ConformanceSignatureEnvelope = {
    formatVersion: '0.1',
    payloadType,
    payloadSha256: reportSha256,
    signatureAlgorithm: 'ed25519',
    identity: options.identity,
    ...(options.issuer === undefined ? {} : { issuer: options.issuer }),
    publicKey: {
      format: 'spki-pem',
      sha256: publicKeySha256,
      value: publicKeyPem
    },
    signatureBase64: signature.toString('base64')
  };
  assertValidEnvelope(envelope);
  return {
    reportBytes,
    envelopeBytes: Buffer.from(`${JSON.stringify(envelope, null, 2)}\n`),
    reportSha256,
    publicKeySha256,
    payloadType
  };
}

export function verifyConformanceReport(
  reportBytes: Uint8Array,
  envelopeBytes: Uint8Array,
  options: VerifyConformanceReportOptions
): VerifiedConformanceReport {
  validateIdentity(options.expectedIdentity, 'expected identity');
  if (!/^[a-f0-9]{64}$/u.test(options.expectedPublicKeySha256)) {
    throw new PolicyError(
      'invalid_expected_key',
      'expected public-key SHA-256 must be 64 lowercase hexadecimal characters'
    );
  }
  if (options.expectedIssuer !== undefined) {
    validateIdentity(options.expectedIssuer, 'expected issuer');
  }
  const envelope = parseEnvelope(envelopeBytes);
  const { report } = parseReport(reportBytes, envelope.payloadType);
  if (report.status !== 'verified' || !report.verification) {
    throw new PolicyError('report_not_verified', 'report status must be verified');
  }
  const reportSha256 = sha256(reportBytes);
  if (envelope.payloadSha256 !== reportSha256) {
    throw new PolicyError('report_digest_mismatch', 'report bytes do not match the signed digest');
  }
  const reportVerification = report.verification;
  if (
    envelope.identity !== options.expectedIdentity ||
    reportVerification.identity !== options.expectedIdentity
  ) {
    throw new PolicyError('verification_identity_mismatch', 'report signer identity is not trusted');
  }
  const expectedIssuer = options.expectedIssuer ?? null;
  if (
    (envelope.issuer ?? null) !== expectedIssuer ||
    (reportVerification.issuer ?? null) !== expectedIssuer
  ) {
    throw new PolicyError('verification_issuer_mismatch', 'report signer issuer is not trusted');
  }
  const publicKey = parseEd25519PublicKey(envelope.publicKey.value);
  const publicKeySha256 = sha256(exportPublicKeyDer(publicKey));
  if (
    publicKeySha256 !== envelope.publicKey.sha256 ||
    publicKeySha256 !== reportVerification.publicKeySha256 ||
    publicKeySha256 !== options.expectedPublicKeySha256
  ) {
    throw new PolicyError('verification_key_mismatch', 'report signer public key is not trusted');
  }
  const signature = decodeSignature(envelope.signatureBase64);
  if (!verifyBytes(null, signatureMessage(envelope.payloadType, reportSha256), publicKey, signature)) {
    throw new PolicyError('invalid_report_signature', 'conformance report signature is invalid');
  }
  return {
    verified: true,
    reportSha256,
    publicKeySha256,
    identity: options.expectedIdentity,
    issuer: expectedIssuer,
    payloadType: envelope.payloadType
  };
}

function parseReport(
  bytes: Uint8Array,
  expectedType?: ConformanceReportMediaType
): { report: ConformanceReport; payloadType: ConformanceReportMediaType } {
  const value = parseJson(bytes, MAX_CONFORMANCE_REPORT_BYTES, 'report');
  if (
    expectedType === CONFORMANCE_REPORT_MEDIA_TYPE ||
    (expectedType === undefined && validateReport(value))
  ) {
    if (!validateReport(value)) {
      throw schemaError(
        'report_schema_validation',
        'harness conformance report',
        validateReport.errors ?? []
      );
    }
    return { report: value, payloadType: CONFORMANCE_REPORT_MEDIA_TYPE };
  }
  if (
    expectedType === IMPLEMENTATION_CONFORMANCE_REPORT_MEDIA_TYPE ||
    (expectedType === undefined && validateImplementationReport(value))
  ) {
    if (!validateImplementationReport(value)) {
      throw schemaError(
        'report_schema_validation',
        'implementation conformance report',
        validateImplementationReport.errors ?? []
      );
    }
    assertImplementationConformanceReport(value as unknown as ImplementationConformanceReport);
    return { report: value, payloadType: IMPLEMENTATION_CONFORMANCE_REPORT_MEDIA_TYPE };
  }
  const errors = [
    ...(validateReport.errors ?? []),
    ...(validateImplementationReport.errors ?? [])
  ];
  throw schemaError('report_schema_validation', 'conformance report', errors);
}

function parseEnvelope(bytes: Uint8Array): ConformanceSignatureEnvelope {
  const value = parseJson(bytes, MAX_CONFORMANCE_ENVELOPE_BYTES, 'envelope');
  if (!validateEnvelope(value)) {
    throw schemaError(
      'envelope_schema_validation',
      'signature envelope',
      validateEnvelope.errors ?? []
    );
  }
  return value;
}

function parseJson(bytes: Uint8Array, maximum: number, label: string): unknown {
  if (bytes.byteLength > maximum) {
    throw new PolicyError(`${label}_too_large`, `${label} exceeds ${maximum} bytes`);
  }
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new PolicyError(`invalid_${label}_encoding`, `${label} is not valid UTF-8`);
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new PolicyError(`invalid_${label}_json`, `${label} is not valid JSON`);
  }
}

function assertValidReport(report: ConformanceReport, payloadType: ConformanceReportMediaType): void {
  const validator =
    payloadType === CONFORMANCE_REPORT_MEDIA_TYPE ? validateReport : validateImplementationReport;
  if (!validator(report)) {
    throw schemaError('report_schema_validation', 'conformance report', validator.errors ?? []);
  }
}

function assertValidEnvelope(envelope: ConformanceSignatureEnvelope): void {
  if (!validateEnvelope(envelope)) {
    throw schemaError(
      'envelope_schema_validation',
      'signature envelope',
      validateEnvelope.errors ?? []
    );
  }
}

function parseEd25519PrivateKey(bytes: Uint8Array | string): KeyObject {
  let key: KeyObject;
  try {
    key = createPrivateKey(typeof bytes === 'string' ? bytes : Buffer.from(bytes));
  } catch {
    throw new PolicyError('invalid_private_key', 'private key must be valid PKCS#8 PEM');
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new PolicyError('invalid_private_key', 'private key must use Ed25519');
  }
  return key;
}

function parseEd25519PublicKey(value: string): KeyObject {
  let key: KeyObject;
  try {
    key = createPublicKey(value);
  } catch {
    throw new PolicyError('invalid_public_key', 'envelope public key is invalid');
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new PolicyError('invalid_public_key', 'envelope public key must use Ed25519');
  }
  return key;
}

function exportPublicKeyDer(key: KeyObject): Uint8Array {
  return key.export({ type: 'spki', format: 'der' });
}

function decodeSignature(value: string): Uint8Array {
  const signature = Buffer.from(value, 'base64');
  if (signature.byteLength !== 64 || signature.toString('base64') !== value) {
    throw new PolicyError('invalid_report_signature', 'signature must be canonical Ed25519 base64');
  }
  return signature;
}

function signatureMessage(payloadType: ConformanceReportMediaType, reportSha256: string): Uint8Array {
  const domain =
    payloadType === CONFORMANCE_REPORT_MEDIA_TYPE
      ? 'AIIGNORE-CONFORMANCE-REPORT-SIGNATURE-V0.1\0'
      : 'AIIGNORE-IMPLEMENTATION-CONFORMANCE-REPORT-SIGNATURE-V0.1\0';
  return Buffer.concat([
    Buffer.from(domain, 'ascii'),
    Buffer.from(reportSha256, 'hex')
  ]);
}

function reportIsDirty(
  report: ConformanceReport,
  payloadType: ConformanceReportMediaType
): boolean {
  return payloadType === CONFORMANCE_REPORT_MEDIA_TYPE
    ? report.sourceTreeDirty === true
    : report.implementation?.sourceTreeDirty === true;
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function validateIdentity(value: string, label: string): void {
  if (value.length === 0 || value.length > 512 || /[\0\r\n]/u.test(value)) {
    throw new PolicyError('invalid_verification_identity', `${label} is invalid`);
  }
}

function schemaError(
  code: string,
  label: string,
  errors: ErrorObject[]
): PolicyError {
  const message = errors
    .slice(0, 20)
    .map((error) => `${error.instancePath || '/'} ${error.message ?? 'is invalid'}`)
    .join('; ');
  const suffix = errors.length > 20 ? `; and ${errors.length - 20} more errors` : '';
  return new PolicyError(code, `${label}: ${message}${suffix}`);
}
