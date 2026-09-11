import { clone, deepFreeze } from '../core/investigation/canonical.js';
import { importInvestigation } from '../core/investigation/model.js';
import { sha256Hex } from '../core/sha256.js';

const REQUIRED = new Set(['hunt', 'result', 'disposition']);
const REPORT_FILENAME = 'investigation-report.txt';
const REPORT_MIME_TYPE = 'text/plain;charset=utf-8';

function unique(values) {
  return [...new Set(values.filter(value => typeof value === 'string' && value))].sort((a, b) => a.localeCompare(b));
}

function sourceReferences(investigation) {
  const values = [];
  for (const snapshot of investigation.evidenceSnapshots) {
    for (const item of snapshot.evidence.evidence ?? []) values.push(...(item.references ?? []));
  }
  for (const artifact of investigation.operatorArtifacts) values.push(...artifact.references);
  values.push(...(investigation.workflow.hunt?.sourceReferences ?? []));
  return unique(values);
}

export function buildInvestigationReport(input) {
  const investigation = importInvestigation(input);
  const stale = investigation.freshness.stale.filter(item => REQUIRED.has(item.artifact));
  if (stale.length) throw new Error(`STALE_DEPENDENCY: ${stale.map(item => item.artifact).join(',')}`);
  if (!investigation.scope.profile || investigation.scope.context === null) throw new Error('REPORT_NOT_READY: scope required');
  if (!investigation.evidenceSnapshots.length) throw new Error('REPORT_NOT_READY: evidence required');
  if (!investigation.workflow.hunt) throw new Error('REPORT_NOT_READY: hunt required');
  if (!investigation.workflow.result) throw new Error('REPORT_NOT_READY: results required');
  if (!investigation.workflow.disposition) throw new Error('REPORT_NOT_READY: disposition required');

  return deepFreeze({
    identity: {
      id: investigation.id,
      title: investigation.title,
      revision: investigation.revision,
      createdAt: investigation.createdAt,
      updatedAt: investigation.updatedAt,
    },
    scope: clone(investigation.scope),
    evidence: investigation.evidenceSnapshots.map(snapshot => ({
      id: snapshot.id,
      type: snapshot.type,
      indicator: snapshot.indicator,
      capturedAt: snapshot.capturedAt,
      requestId: snapshot.requestId,
      evidence: clone(snapshot.evidence),
      diffFromPrevious: clone(snapshot.diffFromPrevious),
    })),
    operatorContext: clone(investigation.operatorArtifacts),
    hunt: clone(investigation.workflow.hunt),
    results: clone(investigation.workflow.result),
    disposition: clone(investigation.workflow.disposition),
    limitations: unique([
      ...investigation.limitations,
      ...(investigation.workflow.result.limitations ?? []),
      ...(investigation.workflow.disposition.limitations ?? []),
    ]),
    provenance: {
      investigationFormat: investigation.format,
      investigationRevision: investigation.revision,
      evidenceSnapshotIds: investigation.evidenceSnapshots.map(item => item.id),
      dependencyFingerprints: clone(investigation.freshness.dependencies),
      sourceReferences: sourceReferences(investigation),
      generated: false,
      projectionOnly: true,
    },
  });
}

function json(value) {
  return JSON.stringify(value, null, 2);
}

export function renderInvestigationText(investigation) {
  const report = buildInvestigationReport(investigation);
  const lines = [
    'PARA11AX INVESTIGATION REPORT',
    `Investigation: ${report.identity.title} [${report.identity.id}]`,
    `Revision: ${report.identity.revision}`,
    '',
    'SCOPE',
    json(report.scope),
    '',
    'AUTHORITATIVE EVIDENCE V2',
    json(report.evidence),
    '',
    'OPERATOR CONTEXT (NOT EVIDENCE V2)',
    json(report.operatorContext),
    '',
    'HUNT PACKAGE',
    json(report.hunt),
    '',
    'IMPORTED RESULT ANALYSIS',
    json(report.results),
    '',
    'ANALYST DISPOSITION',
    json(report.disposition),
    '',
    `LIMITATIONS: ${report.limitations.join('; ') || 'none recorded'}`,
    'Projection only. Query execution, escalation, and ticket submission remain external and require analyst approval.',
  ];
  return `${lines.join('\n')}\n`;
}

export function buildInvestigationManifest(input, { generatedAt } = {}) {
  const investigation = importInvestigation(input);
  // Rendering is the readiness/quality gate: a manifest must never describe an
  // investigation that cannot produce the corresponding report artifact.
  const content = renderInvestigationText(investigation);
  const reportSha256 = sha256Hex(content);
  const timestamp = generatedAt ?? investigation.updatedAt;
  if (typeof timestamp !== 'string' || !Number.isFinite(Date.parse(timestamp))) {
    throw new TypeError('invalid investigation manifest timestamp');
  }

  return deepFreeze({
    manifestVersion: '1.0',
    investigationId: investigation.id,
    investigationRevision: investigation.revision,
    generatedAt: new Date(Date.parse(timestamp)).toISOString(),
    reportSha256,
    files: [{
      name: REPORT_FILENAME,
      mimeType: REPORT_MIME_TYPE,
      encoding: 'utf8',
      bytes: new TextEncoder().encode(content).byteLength,
      sha256: reportSha256,
    }],
  });
}
