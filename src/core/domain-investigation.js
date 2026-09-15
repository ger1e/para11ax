import {
  createDomainInvestigation as createLegacyDomainInvestigation,
  importDomainSurface as importLegacyDomainSurface,
  importDomainVulnerabilities as importLegacyDomainVulnerabilities,
  DOMAIN_INVESTIGATION_SCHEMA_VERSION,
} from './domain-investigation-legacy.js';
import { applyProviderIndependencePolicy } from './domain-investigation-policy.js';
import {
  createPromotionState,
  applyPromotionEvent,
  deriveEffectiveAttestations,
} from './evidence-promotion.js';
import { summarizeProviderIndependence } from './provider-independence.js';
import { buildEvidenceGraph } from './evidence-graph.js';

function optionsObject(options) {
  if (options === undefined || options === null) return {};
  if (typeof options !== 'object' || Array.isArray(options)) throw new TypeError('Domain Investigation options must be an object');
  return options;
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function uniqueSorted(values) {
  return [...new Set(values.filter(value => value !== undefined && value !== null && String(value).length > 0).map(String))].sort();
}

function utf8Bytes(value) {
  return Buffer.byteLength(JSON.stringify(value), 'utf8');
}

function registryFromArtifact(artifact) {
  return artifact?._authoritative?.providerIndependenceRegistry;
}

function promotionFromArtifact(artifact) {
  return artifact?._authoritative?.promotionState ?? null;
}

function validateDomainArtifact(artifact) {
  if (!artifact || artifact.schemaVersion !== DOMAIN_INVESTIGATION_SCHEMA_VERSION || !artifact._authoritative?.enrichment) {
    throw new TypeError('valid Domain Investigation artifact is required');
  }
  return artifact;
}

function buildAuthorityAudit(artifact, effectiveAttestations, promotionState) {
  const recommendations = Array.isArray(artifact?.recommendations) ? artifact.recommendations : [];
  const registryVersions = uniqueSorted(recommendations.map(item => item?.independence?.registryVersion));
  const registryVersion = registryVersions[0]
    ?? artifact?._authoritative?.providerIndependenceRegistry?.version
    ?? 'provider-independence-v1.0';
  const knownQuorumGroups = uniqueSorted(recommendations.flatMap(item =>
    Array.isArray(item?.independence?.quorumGroups) ? item.independence.quorumGroups : []));
  const unknownProviders = uniqueSorted(recommendations.flatMap(item =>
    Array.isArray(item?.independence?.unknownProviders) ? item.independence.unknownProviders : []));
  const effective = [...effectiveAttestations]
    .filter(item => item?.authorityClass === 'analyst_attestation' && item?.id && item?.fingerprint)
    .map(item => ({ id: String(item.id), fingerprint: String(item.fingerprint) }))
    .sort((a, b) => a.id.localeCompare(b.id) || a.fingerprint.localeCompare(b.fingerprint));
  const events = Array.isArray(promotionState?.events) ? promotionState.events : [];
  const eventTypes = ['approved', 'rejected', 'revoked', 'superseded', 'expired'];
  const promotionAudit = Object.fromEntries(eventTypes.map(type => [
    type,
    events.filter(event => event?.type === type).length,
  ]));
  const contradictions = recommendations
    .filter(item => Array.isArray(item?.contradictions) && item.contradictions.length > 0)
    .map(item => ({
      type: String(item.type),
      value: String(item.value),
      count: item.contradictions.length,
    }))
    .sort((a, b) => `${a.type}:${a.value}`.localeCompare(`${b.type}:${b.value}`));

  return {
    registryVersion,
    knownQuorumGroups,
    unknownLineageCount: unknownProviders.length,
    analystAttestations: {
      authorityClass: 'analyst_attestation',
      effective,
    },
    promotionAudit: {
      eventCount: events.length,
      ...promotionAudit,
    },
    contradictions,
  };
}

function augmentReport(report, authorityAudit) {
  const groups = authorityAudit.knownQuorumGroups.length
    ? authorityAudit.knownQuorumGroups.join(', ')
    : 'none';
  const auditText = [
    `Provider independence registry: ${authorityAudit.registryVersion}.`,
    `Known quorum groups: ${groups}; unknown lineage providers: ${authorityAudit.unknownLineageCount}.`,
    `Analyst attestation authority: ${authorityAudit.analystAttestations.authorityClass}; effective attestations: ${authorityAudit.analystAttestations.effective.length}.`,
  ].join('\n');
  return {
    ...report,
    authorityAudit,
    text: `${report?.text ?? ''}\n${auditText}`.trim(),
  };
}

function augmentHandoff(handoff, authorityAudit) {
  const { contextBudget = {}, ...baseHandoff } = handoff ?? {};
  const maximumBytes = Number(contextBudget.maximumBytes) || 128_000;
  const rawEvidenceIncluded = contextBudget.rawEvidenceIncluded === true;
  const base = {
    ...baseHandoff,
    authorityAudit,
  };
  let serializedBytes = 0;
  for (let iteration = 0; iteration < 8; iteration += 1) {
    const projected = {
      ...base,
      contextBudget: { serializedBytes, maximumBytes, rawEvidenceIncluded },
    };
    const actualBytes = utf8Bytes(projected);
    if (actualBytes === serializedBytes) {
      if (actualBytes >= maximumBytes) throw new RangeError('handoff context exceeds bounded context budget');
      return projected;
    }
    serializedBytes = actualBytes;
  }
  throw new RangeError('handoff context budget did not converge');
}

function applyAuthorityAudit(artifact, effectiveAttestations, promotionState) {
  const authorityAudit = buildAuthorityAudit(artifact, effectiveAttestations, promotionState);
  return deepFreeze({
    ...artifact,
    report: augmentReport(artifact.report, authorityAudit),
    handoff: augmentHandoff(artifact.handoff, authorityAudit),
  });
}

function applyAuthorityState(artifact, registry, promotionState) {
  const effectiveAttestations = promotionState
    ? deriveEffectiveAttestations(promotionState.candidates, promotionState.events)
    : [];
  const projected = promotionState
    ? {
        ...artifact,
        promotion: {
          candidates: promotionState.candidates,
          events: promotionState.events,
          effectiveAttestations,
        },
        _authoritative: {
          ...(artifact._authoritative ?? {}),
          promotionState,
        },
      }
    : artifact;
  const policyApplied = applyProviderIndependencePolicy(projected, registry, effectiveAttestations);
  return applyAuthorityAudit(policyApplied, effectiveAttestations, promotionState);
}

function importedObservable(record, kind) {
  if (kind === 'surface') {
    if (record?.url) return { type: 'url', value: record.url };
    if (record?.host) return { type: 'domain', value: record.host };
    if (record?.ip) return { type: 'ip', value: record.ip };
    return null;
  }
  if (record?.cve) return { type: 'cve', value: record.cve };
  if (record?.url) return { type: 'url', value: record.url };
  if (record?.host) return { type: 'domain', value: record.host };
  return null;
}

function operatorArtifactsFromImports(artifact) {
  const capturedAt = artifact?._authoritative?.enrichment?.queriedAt;
  if (typeof capturedAt !== 'string' || Number.isNaN(Date.parse(capturedAt))) return [];
  const sources = [
    ...((Array.isArray(artifact?.imports?.surface) ? artifact.imports.surface : []).map(record => ({ kind: 'surface', record }))),
    ...((Array.isArray(artifact?.imports?.vulnerabilities) ? artifact.imports.vulnerabilities : []).map(record => ({ kind: 'vulnerability', record }))),
  ];
  return sources.flatMap(({ kind, record }) => {
    const observable = importedObservable(record, kind);
    if (!observable || typeof record?.reference !== 'string' || !record.reference) return [];
    const source = typeof record.source === 'string' && record.source ? record.source : `domain-investigation-${kind}-import`;
    const sourceKind = kind === 'surface' ? 'authorized_surface_finding' : 'authorized_vulnerability_finding';
    return [{
      id: record.id,
      kind: sourceKind,
      capturedAt: new Date(capturedAt).toISOString(),
      source,
      summary: `Imported ${kind} operator finding for ${observable.type}:${observable.value}.`,
      references: [record.reference],
      observable,
      observation: { kind: 'operator_finding', verdict: 'observed' },
    }];
  });
}

export function createDomainInvestigation(enrichment, expectedTarget, options) {
  const normalizedOptions = optionsObject(options);
  const artifact = createLegacyDomainInvestigation(enrichment, expectedTarget);
  const promotionState = normalizedOptions.operatorArtifacts
    ? createPromotionState(normalizedOptions.operatorArtifacts)
    : null;
  return applyAuthorityState(artifact, normalizedOptions.providerIndependenceRegistry, promotionState);
}

export function importDomainSurface(artifact, input) {
  const registry = registryFromArtifact(artifact);
  const promotionState = promotionFromArtifact(artifact);
  const rebuilt = importLegacyDomainSurface(artifact, input);
  return applyAuthorityState(rebuilt, registry, promotionState);
}

export function importDomainVulnerabilities(artifact, input) {
  const registry = registryFromArtifact(artifact);
  const promotionState = promotionFromArtifact(artifact);
  const rebuilt = importLegacyDomainVulnerabilities(artifact, input);
  return applyAuthorityState(rebuilt, registry, promotionState);
}

export function initializeDomainPromotion(artifact, operatorArtifacts) {
  validateDomainArtifact(artifact);
  const promotionState = createPromotionState(operatorArtifacts);
  return applyAuthorityState(artifact, registryFromArtifact(artifact), promotionState);
}

export function initializeDomainPromotionFromImports(artifact) {
  validateDomainArtifact(artifact);
  if (promotionFromArtifact(artifact)) return artifact;
  return initializeDomainPromotion(artifact, operatorArtifactsFromImports(artifact));
}

export function applyDomainPromotionEvent(artifact, event) {
  validateDomainArtifact(artifact);
  const current = promotionFromArtifact(artifact);
  if (!current) throw new TypeError('Domain Investigation promotion state is not initialized');
  const next = applyPromotionEvent(current, event);
  return applyAuthorityState(artifact, registryFromArtifact(artifact), next);
}

export function buildDomainInvestigationGraph(artifact) {
  validateDomainArtifact(artifact);
  const enrichment = artifact._authoritative.enrichment;
  const evidence = Array.isArray(enrichment.evidence) ? enrichment.evidence : [];
  const providers = uniqueSorted(evidence.map(item => item?.provider).filter(Boolean));
  const independence = summarizeProviderIndependence(providers, registryFromArtifact(artifact));
  return buildEvidenceGraph({
    indicator: artifact.target.value,
    type: artifact.target.type,
    evidence,
    relationships: Array.isArray(enrichment.relationships) ? enrichment.relationships : [],
    correlation: enrichment.correlation ?? {},
    decision: enrichment.decision ?? {},
    providerIndependence: independence,
    promotion: artifact.promotion ?? {},
    recommendations: artifact.recommendations ?? [],
  });
}

export { DOMAIN_INVESTIGATION_SCHEMA_VERSION };
