import { readFileSync } from 'node:fs';
import { parse } from 'yaml';

const metadata = parse(readFileSync('security-insights.yml', 'utf8'));
const failures = [];
const required = (path, expectedType) => {
  const value = path.split('.').reduce((current, key) => current?.[key], metadata);
  if (typeof value !== expectedType) failures.push(`${path} must be a ${expectedType}`);
  return value;
};

if (required('header.schema-version', 'string') !== '2.2.0') {
  failures.push('header.schema-version must be the reviewed Security Insights version 2.2.0');
}
for (const field of ['header.last-updated', 'header.last-reviewed']) {
  const value = required(field, 'string');
  if (typeof value === 'string' && !/^\d{4}-\d{2}-\d{2}$/u.test(value)) {
    failures.push(`${field} must use YYYY-MM-DD`);
  }
}
for (const field of [
  'header.url',
  'project.homepage',
  'repository.url',
  'repository.license.url',
  'project.vulnerability-reporting.policy'
]) {
  const value = required(field, 'string');
  if (typeof value === 'string' && !/^https:\/\/[^\s]+$/u.test(value)) {
    failures.push(`${field} must be an HTTPS URL`);
  }
}
if (required('project.name', 'string') !== 'aiignore') failures.push('project.name must be aiignore');
if (required('repository.status', 'string') !== 'WIP') {
  failures.push('repository.status must remain WIP for the experimental alpha');
}
if (required('repository.license.expression', 'string') !== 'MIT') {
  failures.push('repository.license.expression must match the repository license');
}
if (required('project.vulnerability-reporting.reports-accepted', 'boolean') !== true) {
  failures.push('vulnerability reports must be accepted');
}
if (!Array.isArray(metadata?.project?.administrators) || metadata.project.administrators.length === 0) {
  failures.push('project.administrators must name at least one administrator');
}
if (!Array.isArray(metadata?.repository?.['core-team']) || metadata.repository['core-team'].length === 0) {
  failures.push('repository.core-team must name at least one maintainer');
}
if (typeof metadata?.repository?.security?.assessments?.self?.comment !== 'string') {
  failures.push('repository.security.assessments.self must disclose the self-assessment status');
}

if (failures.length > 0) {
  failures.forEach((failure) => process.stderr.write(`not ok - ${failure}\n`));
  process.exit(1);
}
process.stdout.write('ok - Security Insights 2.2.0 required metadata and alpha disclosures\n');
