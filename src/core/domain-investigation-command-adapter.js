import { shellError } from '../../app/shell-core/errors.js';
import {
  createDomainInvestigation,
  importDomainSurface,
  importDomainVulnerabilities,
  initializeDomainPromotionFromImports,
  applyDomainPromotionEvent,
  buildDomainInvestigationGraph,
} from './domain-investigation.js';
import { toDomainInvestigationStix } from '../export/domain-investigation-stix.js';

export const DOMAIN_INVESTIGATION_HANDLERS = Object.freeze([
  'domain-investigation-build',
  'domain-investigation-surface-import',
  'domain-investigation-vulnerability-import',
  'domain-investigation-show',
  'domain-investigation-report',
  'domain-investigation-stix',
  'domain-investigation-handoff',
  'domain-investigation-promotion-candidates',
  'domain-investigation-promote',
  'domain-investigation-reject-promotion',
  'domain-investigation-revoke-promotion',
  'domain-investigation-graph',
  'domain-investigation-clear',
]);

const typedRecord = value => Object.freeze({ type: 'record', value });
const typedRecords = value => Object.freeze({ type: 'records', value });
const typedText = value => Object.freeze({ type: 'text', value: String(value ?? '') });
const typedGraph = value => Object.freeze({ type: 'graph', value });

function parseJson(content, label) {
  try { return JSON.parse(content); }
  catch { throw new TypeError(`${label} must be valid JSON`); }
}

function publicProjection(artifact) {
  const { _authoritative, ...projection } = artifact;
  void _authoritative;
  return Object.freeze(structuredClone(projection));
}

function noArgs(args, usage) {
  if (args.length) throw shellError('INVALID_ARGUMENT', `usage: ${usage}`);
}

function inlineJson(args, label, usage) {
  if (!Array.isArray(args) || args.length === 0 || String(args[0]).startsWith('--')) {
    throw shellError('INVALID_ARGUMENT', `usage: ${usage}`);
  }
  return parseJson(args.join(' '), label);
}

async function contentFor(args, kind, loadContent) {
  const transport = args.length === 0 || String(args[0]).startsWith('--');
  if (!transport) return args.join(' ');
  if (typeof loadContent !== 'function') throw shellError('POLICY_DENIED', 'Domain Investigation content transport unavailable');
  const value = await loadContent({ kind, args: [...args] });
  if (typeof value !== 'string') throw new TypeError('Domain Investigation transport must return UTF-8 text');
  return value;
}

function requireArtifact(value) {
  if (!value || value.schemaVersion !== 'domain-investigation-v1.0' || !value._authoritative?.enrichment) {
    throw new TypeError('Domain Investigation build is required');
  }
  return value;
}

function normalizeError(error) {
  if (error?.code) return error;
  if (error instanceof RangeError && /limit|exceed|large|budget/i.test(error.message)) {
    return shellError('OUTPUT_LIMIT', 'Domain Investigation input exceeds a fixed limit');
  }
  return shellError('INVALID_ARGUMENT', 'invalid Domain Investigation input');
}

export async function executeDomainInvestigationCommand({
  handler,
  args = [],
  artifact = null,
  loadContent = null,
} = {}) {
  try {
    if (!DOMAIN_INVESTIGATION_HANDLERS.includes(handler)) throw new TypeError('unsupported Domain Investigation handler');
    if (!Array.isArray(args)) throw new TypeError('Domain Investigation arguments required');

    if (handler === 'domain-investigation-build') {
      const content = await contentFor(args, 'domain-enrichment', loadContent);
      const next = createDomainInvestigation(parseJson(content, 'Evidence v2 enrichment'));
      return Object.freeze({ output: typedRecord(publicProjection(next)), artifact: next });
    }

    if (handler === 'domain-investigation-clear') {
      noArgs(args, 'domain-investigation clear');
      return Object.freeze({ output: typedRecord({ cleared: true }), artifact: null });
    }

    const current = requireArtifact(artifact);
    if (handler === 'domain-investigation-surface-import') {
      const content = await contentFor(args, 'domain-surface', loadContent);
      const next = importDomainSurface(current, parseJson(content, 'surface import'));
      return Object.freeze({ output: typedRecord(publicProjection(next)), artifact: next });
    }
    if (handler === 'domain-investigation-vulnerability-import') {
      const content = await contentFor(args, 'domain-vulnerability', loadContent);
      const next = importDomainVulnerabilities(current, parseJson(content, 'vulnerability import'));
      return Object.freeze({ output: typedRecord(publicProjection(next)), artifact: next });
    }
    if (handler === 'domain-investigation-show') {
      noArgs(args, 'domain-investigation show');
      return Object.freeze({ output: typedRecord(publicProjection(current)), artifact: current });
    }
    if (handler === 'domain-investigation-report') {
      noArgs(args, 'domain-investigation report');
      return Object.freeze({ output: typedText(current.report.text), artifact: current });
    }
    if (handler === 'domain-investigation-stix') {
      noArgs(args, 'domain-investigation stix');
      return Object.freeze({ output: typedRecord(toDomainInvestigationStix(current)), artifact: current });
    }
    if (handler === 'domain-investigation-handoff') {
      noArgs(args, 'domain-investigation handoff');
      return Object.freeze({ output: typedRecord(current.handoff), artifact: current });
    }
    if (handler === 'domain-investigation-promotion-candidates') {
      noArgs(args, 'domain-investigation promotion-candidates');
      const next = initializeDomainPromotionFromImports(current);
      return Object.freeze({ output: typedRecords(next.promotion?.candidates ?? []), artifact: next });
    }
    if (handler === 'domain-investigation-promote') {
      const decision = inlineJson(args, 'promotion approval', 'domain-investigation promote <approval-json>');
      const initialized = initializeDomainPromotionFromImports(current);
      const next = applyDomainPromotionEvent(initialized, { ...decision, type: 'approved' });
      return Object.freeze({ output: typedRecord(publicProjection(next)), artifact: next });
    }
    if (handler === 'domain-investigation-reject-promotion') {
      const decision = inlineJson(args, 'promotion rejection', 'domain-investigation reject-promotion <decision-json>');
      const initialized = initializeDomainPromotionFromImports(current);
      const next = applyDomainPromotionEvent(initialized, { ...decision, type: 'rejected' });
      return Object.freeze({ output: typedRecord(publicProjection(next)), artifact: next });
    }
    if (handler === 'domain-investigation-revoke-promotion') {
      const decision = inlineJson(args, 'promotion revocation', 'domain-investigation revoke-promotion <decision-json>');
      const initialized = initializeDomainPromotionFromImports(current);
      const next = applyDomainPromotionEvent(initialized, { ...decision, type: 'revoked' });
      return Object.freeze({ output: typedRecord(publicProjection(next)), artifact: next });
    }
    if (handler === 'domain-investigation-graph') {
      noArgs(args, 'domain-investigation graph');
      return Object.freeze({ output: typedGraph(buildDomainInvestigationGraph(current)), artifact: current });
    }
    throw new TypeError('unsupported Domain Investigation handler');
  } catch (error) {
    throw normalizeError(error);
  }
}
