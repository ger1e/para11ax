import { sha256Hex } from './sha256.js';

export const EVIDENCE_GRAPH_SCHEMA_VERSION = '1.0';

const LIMITS = Object.freeze({
  nodes: 256,
  edges: 512,
  evidence: 100,
  attack: 64,
  actor: 32,
  malware: 32,
  providerIndependence: 256,
  operatorArtifacts: 256,
  promotionCandidates: 256,
  promotionEvents: 512,
  promotedEvidence: 256,
  recommendations: 256,
});

const FINGERPRINT = /^[0-9a-f]{64}$/i;
const ATTACK_ID = /^T\d{4}(?:\.\d{3})?$/i;
const OBSERVABLE_TYPES = new Set(['ip', 'domain', 'url', 'hash', 'cve', 'asn', 'cidr', 'certificate']);
const RELATION_TYPE_MAP = Object.freeze({ hostname: 'domain', nameserver: 'domain', mx: 'domain' });

const fail = code => { throw new Error(code); };

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize(value[key])]));
  }
  return value;
}

function stableJson(value) {
  return JSON.stringify(canonicalize(value));
}

function deepFreeze(value, seen = new Set()) {
  if (!value || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function normalizedText(value) {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function canonicalObservableValue(type, value) {
  const normalizedType = String(type ?? '').toLowerCase();
  const text = String(value ?? '').trim();
  if (normalizedType === 'hash' || normalizedType === 'domain') return text.toLowerCase();
  if (normalizedType === 'cve' || normalizedType === 'asn') return text.toUpperCase();
  return text;
}

function observableNode(type, value) {
  const normalizedType = String(type ?? '').toLowerCase();
  const normalizedValue = canonicalObservableValue(normalizedType, value);
  if (!normalizedType || !normalizedValue) fail('evidence_graph_observable_invalid');
  return {
    id: `observable:${normalizedType}:${sha256Hex(`${normalizedType}\u0000${normalizedValue}`).slice(0, 24)}`,
    type: 'observable',
    observableType: normalizedType,
    value: normalizedValue,
  };
}

function actorNode(name) {
  return { id: `actor:${sha256Hex(name).slice(0, 24)}`, type: 'actor', name };
}

function malwareNode(name) {
  return { id: `malware:${sha256Hex(name).slice(0, 24)}`, type: 'malware', name };
}

function attackNode(id) {
  const attackId = String(id ?? '').toUpperCase();
  if (!ATTACK_ID.test(attackId)) return null;
  return { id: `attack:${attackId}`, type: 'attack', attackId };
}

function relationshipKind(relation) {
  return normalizedText(relation?.type) ?? normalizedText(relation?.relationship) ?? null;
}

function relationTargetType(relation) {
  const explicit = normalizedText(relation?.targetType)?.toLowerCase() ?? null;
  if (explicit) {
    if (RELATION_TYPE_MAP[explicit]) return RELATION_TYPE_MAP[explicit];
    if (OBSERVABLE_TYPES.has(explicit) || ['attack', 'actor', 'malware'].includes(explicit)) return explicit;
    return null;
  }
  const relationType = relationshipKind(relation)?.toLowerCase() ?? null;
  return relationType ? (RELATION_TYPE_MAP[relationType] ?? null) : null;
}

function edgeIdentity(type, source, target, data) {
  return `edge:${sha256Hex(`${type}\u0000${source}\u0000${target}\u0000${stableJson(data ?? {})}`).slice(0, 24)}`;
}

function boundedArray(value, limit, code) {
  if (!Array.isArray(value) || value.length > limit) fail(code);
  return value;
}

function projectionNodeId(type, identity) {
  return `${type}:${sha256Hex(stableJson(identity)).slice(0, 24)}`;
}

export function buildEvidenceGraph({
  indicator,
  type,
  evidence = [],
  relationships = [],
  correlation = {},
  decision = {},
  providerIndependence = {},
  operatorArtifacts = [],
  promotion = {},
  recommendations = [],
} = {}) {
  boundedArray(evidence, LIMITS.evidence, 'evidence_graph_evidence_limit');
  if (!Array.isArray(relationships)) fail('evidence_graph_relationships_invalid');
  boundedArray(operatorArtifacts, LIMITS.operatorArtifacts, 'evidence_graph_operator_artifact_limit');
  boundedArray(recommendations, LIMITS.recommendations, 'evidence_graph_recommendation_limit');

  const resolvedIndependence = providerIndependence?.resolved ?? [];
  boundedArray(resolvedIndependence, LIMITS.providerIndependence, 'evidence_graph_provider_independence_limit');
  const promotionCandidates = promotion?.candidates ?? [];
  const promotionEvents = promotion?.events ?? [];
  const effectiveAttestations = promotion?.effectiveAttestations ?? [];
  boundedArray(promotionCandidates, LIMITS.promotionCandidates, 'evidence_graph_promotion_candidate_limit');
  boundedArray(promotionEvents, LIMITS.promotionEvents, 'evidence_graph_promotion_event_limit');
  boundedArray(effectiveAttestations, LIMITS.promotedEvidence, 'evidence_graph_promoted_evidence_limit');

  const authorityProjectionActive = resolvedIndependence.length > 0
    || operatorArtifacts.length > 0
    || promotionCandidates.length > 0
    || promotionEvents.length > 0
    || effectiveAttestations.length > 0
    || recommendations.length > 0;

  const nodes = new Map();
  const edges = new Map();
  const countsByType = { attack: 0, actor: 0, malware: 0 };
  const exactValueIndex = new Map();

  function indexNode(node) {
    if (node.type === 'observable') {
      const key = `${node.observableType}\u0000${canonicalObservableValue(node.observableType, node.value)}`;
      if (!exactValueIndex.has(key)) exactValueIndex.set(key, []);
      exactValueIndex.get(key).push(node.id);
    } else if (node.type === 'actor' || node.type === 'malware') {
      const key = `${node.type}\u0000${String(node.name)}`;
      if (!exactValueIndex.has(key)) exactValueIndex.set(key, []);
      exactValueIndex.get(key).push(node.id);
    } else if (node.type === 'attack') {
      const key = `attack\u0000${String(node.attackId).toUpperCase()}`;
      if (!exactValueIndex.has(key)) exactValueIndex.set(key, []);
      exactValueIndex.get(key).push(node.id);
    }
  }

  function addNode(node) {
    const existing = nodes.get(node.id);
    if (existing) return existing.id;
    if (nodes.size >= LIMITS.nodes) fail('evidence_graph_node_limit');
    if (Object.hasOwn(countsByType, node.type)) {
      if (countsByType[node.type] >= LIMITS[node.type]) fail(`evidence_graph_${node.type}_limit`);
      countsByType[node.type] += 1;
    }
    const detached = structuredClone(node);
    nodes.set(detached.id, detached);
    indexNode(detached);
    return detached.id;
  }

  function addEdge(typeName, source, target, data = {}) {
    if (!source || !target || source === target || !nodes.has(source) || !nodes.has(target)) return null;
    const cleanData = canonicalize(Object.fromEntries(Object.entries(data).filter(([, value]) => value !== undefined && value !== null && value !== '')));
    const id = edgeIdentity(typeName, source, target, cleanData);
    if (edges.has(id)) return id;
    if (edges.size >= LIMITS.edges) fail('evidence_graph_edge_limit');
    edges.set(id, { id, type: typeName, source, target, data: cleanData });
    return id;
  }

  function observableId(observable, fallbackType = type, fallbackValue = indicator) {
    const observableType = normalizedText(observable?.type) ?? fallbackType;
    const observableValue = normalizedText(observable?.value) ?? fallbackValue;
    if (!observableType || !observableValue) return null;
    return addNode(observableNode(observableType, observableValue));
  }

  const root = observableNode(type, indicator);
  const rootId = addNode(root);
  const evidenceByFingerprint = new Map();
  const providerByName = new Map();

  const orderedEvidence = [...evidence].sort((a, b) => {
    const af = String(a?.integrity?.fingerprint ?? '').toLowerCase();
    const bf = String(b?.integrity?.fingerprint ?? '').toLowerCase();
    return af.localeCompare(bf) || String(a?.provider ?? '').localeCompare(String(b?.provider ?? '')) || stableJson(a).localeCompare(stableJson(b));
  });

  for (const item of orderedEvidence) {
    const fingerprint = String(item?.integrity?.fingerprint ?? '').toLowerCase();
    if (!FINGERPRINT.test(fingerprint)) fail('evidence_graph_fingerprint_invalid');
    const provider = normalizedText(item?.provider);
    if (!provider) fail('evidence_graph_provider_invalid');

    const evidenceId = addNode({
      id: `evidence:${fingerprint}`,
      type: 'evidence',
      fingerprint,
      provider,
      observationKind: normalizedText(item?.observation?.kind),
      verdict: normalizedText(item?.observation?.verdict),
    });
    evidenceByFingerprint.set(fingerprint, evidenceId);
    const providerId = addNode({ id: `provider:${provider}`, type: 'provider', name: provider });
    providerByName.set(provider.toLocaleLowerCase('en-US'), providerId);
    addEdge('has_evidence', rootId, evidenceId);
    addEdge('reported_by', evidenceId, providerId);
    if (authorityProjectionActive) addEdge('supports', evidenceId, rootId);

    const attackIds = Array.isArray(item?.observation?.attributes?.attackIds) ? item.observation.attributes.attackIds : [];
    for (const rawId of [...new Set(attackIds.map(value => String(value).toUpperCase()))].sort()) {
      const node = attackNode(rawId);
      if (!node) continue;
      const attackId = addNode(node);
      addEdge('mapped_to_attack', evidenceId, attackId, { provider });
    }

    const actor = normalizedText(item?.observation?.actor);
    if (actor) {
      const actorId = addNode(actorNode(actor));
      addEdge('reported_actor_context', evidenceId, actorId, { provider });
    }

    const malware = normalizedText(item?.observation?.malwareFamily);
    if (malware) {
      const malwareId = addNode(malwareNode(malware));
      addEdge('reported_malware_context', evidenceId, malwareId, { provider });
    }
  }

  const independenceGroups = new Map();
  const orderedIndependence = [...resolvedIndependence].sort((a, b) =>
    String(a?.provider ?? '').localeCompare(String(b?.provider ?? '')) || stableJson(a).localeCompare(stableJson(b)));
  for (const entry of orderedIndependence) {
    const provider = normalizedText(entry?.provider);
    const group = normalizedText(entry?.independenceGroup);
    if (!provider || !group) continue;
    const providerKey = provider.toLocaleLowerCase('en-US');
    const providerId = providerByName.get(providerKey)
      ?? addNode({ id: `provider:${provider}`, type: 'provider', name: provider });
    providerByName.set(providerKey, providerId);
    const quorumEligible = entry?.quorumEligible === true;
    const groupId = addNode({
      id: projectionNodeId('independence_group', group),
      type: 'independence_group',
      name: group,
      lineageConfidence: normalizedText(entry?.lineageConfidence),
      basis: normalizedText(entry?.basis),
      quorumEligible,
    });
    const existing = independenceGroups.get(group);
    if (!existing || (!existing.quorumEligible && quorumEligible)) {
      independenceGroups.set(group, { id: groupId, quorumEligible });
    }
    addEdge('member_of', providerId, groupId, {
      lineageConfidence: normalizedText(entry?.lineageConfidence),
      basis: normalizedText(entry?.basis),
      quorumEligible,
    });
  }

  const artifactBySourceId = new Map();
  const orderedArtifacts = [...operatorArtifacts].sort((a, b) => stableJson(a).localeCompare(stableJson(b)));
  for (const artifact of orderedArtifacts) {
    const sourceArtifactId = normalizedText(artifact?.id) ?? normalizedText(artifact?.sourceArtifactId);
    if (!sourceArtifactId) continue;
    const artifactId = addNode({
      id: projectionNodeId('operator_artifact', sourceArtifactId),
      type: 'operator_artifact',
      sourceArtifactId,
      sourceKind: normalizedText(artifact?.kind) ?? normalizedText(artifact?.sourceKind),
      source: normalizedText(artifact?.source),
      capturedAt: normalizedText(artifact?.capturedAt),
    });
    artifactBySourceId.set(sourceArtifactId, artifactId);
    const targetId = observableId(artifact?.observable);
    if (targetId) addEdge('describes', artifactId, targetId);
  }

  const candidateById = new Map();
  const candidateToArtifact = new Map();
  const orderedCandidates = [...promotionCandidates].sort((a, b) => String(a?.id ?? '').localeCompare(String(b?.id ?? '')) || stableJson(a).localeCompare(stableJson(b)));
  for (const candidate of orderedCandidates) {
    const candidateKey = normalizedText(candidate?.id);
    const sourceArtifactId = normalizedText(candidate?.sourceArtifactId);
    if (!candidateKey || !sourceArtifactId) continue;
    let artifactId = artifactBySourceId.get(sourceArtifactId);
    if (!artifactId) {
      artifactId = addNode({
        id: projectionNodeId('operator_artifact', sourceArtifactId),
        type: 'operator_artifact',
        sourceArtifactId,
        sourceKind: normalizedText(candidate?.sourceKind),
        source: normalizedText(candidate?.source),
        capturedAt: normalizedText(candidate?.capturedAt),
      });
      artifactBySourceId.set(sourceArtifactId, artifactId);
      const describedId = observableId(candidate?.observable);
      if (describedId) addEdge('describes', artifactId, describedId);
    }
    const candidateId = addNode({
      id: projectionNodeId('promotion_candidate', candidateKey),
      type: 'promotion_candidate',
      candidateId: candidateKey,
      fingerprint: normalizedText(candidate?.fingerprint),
      status: normalizedText(candidate?.status) ?? 'candidate',
    });
    candidateById.set(candidateKey, candidateId);
    candidateToArtifact.set(candidateKey, artifactId);
    addEdge('candidate_for', artifactId, candidateId);
    addEdge('derived_from', candidateId, artifactId);
  }

  const attestationById = new Map();
  const attestationByCandidateId = new Map();
  const orderedAttestations = [...effectiveAttestations].sort((a, b) => String(a?.id ?? '').localeCompare(String(b?.id ?? '')) || stableJson(a).localeCompare(stableJson(b)));
  for (const attestation of orderedAttestations) {
    const attestationKey = normalizedText(attestation?.id);
    const sourceArtifactId = normalizedText(attestation?.sourceArtifactId);
    if (!attestationKey || !sourceArtifactId) continue;
    const candidateKey = normalizedText(attestation?.provenance?.candidateId);
    let artifactId = artifactBySourceId.get(sourceArtifactId);
    if (!artifactId) {
      artifactId = addNode({
        id: projectionNodeId('operator_artifact', sourceArtifactId),
        type: 'operator_artifact',
        sourceArtifactId,
        sourceKind: normalizedText(attestation?.provenance?.sourceKind),
        source: normalizedText(attestation?.provenance?.source),
        capturedAt: normalizedText(attestation?.provenance?.capturedAt),
      });
      artifactBySourceId.set(sourceArtifactId, artifactId);
    }
    const promotedId = addNode({
      id: projectionNodeId('promoted_evidence', attestationKey),
      type: 'promoted_evidence',
      attestationId: attestationKey,
      fingerprint: normalizedText(attestation?.fingerprint),
      authority: normalizedText(attestation?.authority),
      authorityClass: normalizedText(attestation?.authorityClass),
      actorLabel: normalizedText(attestation?.actorLabel),
      approvedAt: normalizedText(attestation?.approvedAt),
    });
    attestationById.set(attestationKey, promotedId);
    if (candidateKey) attestationByCandidateId.set(candidateKey, promotedId);
    addEdge('promoted_from', promotedId, artifactId);
    const targetId = observableId(attestation?.observable);
    if (targetId) addEdge('supports', promotedId, targetId);
  }

  const orderedEvents = [...promotionEvents].sort((a, b) =>
    String(a?.at ?? '').localeCompare(String(b?.at ?? ''))
      || String(a?.id ?? '').localeCompare(String(b?.id ?? ''))
      || stableJson(a).localeCompare(stableJson(b)));
  for (const event of orderedEvents) {
    const eventKey = normalizedText(event?.id) ?? stableJson(event);
    const eventId = addNode({
      id: projectionNodeId('promotion_event', eventKey),
      type: 'promotion_event',
      eventId: normalizedText(event?.id),
      eventType: normalizedText(event?.type),
      at: normalizedText(event?.at),
      actorLabel: normalizedText(event?.actorLabel),
    });
    const affectedId = (normalizedText(event?.attestationId) && attestationById.get(event.attestationId))
      || (normalizedText(event?.candidateId) && attestationByCandidateId.get(event.candidateId))
      || null;
    if (affectedId) addEdge('affects', eventId, affectedId, { eventType: normalizedText(event?.type) });
  }

  const orderedRecommendations = [...recommendations].sort((a, b) => stableJson(a).localeCompare(stableJson(b)));
  for (const recommendation of orderedRecommendations) {
    const recommendationObservableId = observableId({
      type: recommendation?.type,
      value: recommendation?.value,
    });
    if (!recommendationObservableId) continue;
    const evidenceFingerprints = Array.isArray(recommendation?.evidenceFingerprints)
      ? [...new Set(recommendation.evidenceFingerprints.map(value => String(value).toLowerCase()))].sort()
      : [];
    const analystAttestations = Array.isArray(recommendation?.analystAttestations)
      ? [...new Set(recommendation.analystAttestations.map(String))].sort()
      : [];
    const quorumGroups = Array.isArray(recommendation?.uniqueQuorumGroups)
      ? [...new Set(recommendation.uniqueQuorumGroups.map(String))].sort()
      : Array.isArray(recommendation?.independence?.quorumGroups)
        ? [...new Set(recommendation.independence.quorumGroups.map(String))].sort()
        : [];
    const contradictions = Array.isArray(recommendation?.contradictions)
      ? canonicalize(recommendation.contradictions)
      : [];
    const recommendationCore = {
      observableType: normalizedText(recommendation?.type),
      observableValue: normalizedText(recommendation?.value),
      ruleId: normalizedText(recommendation?.ruleId),
      disposition: normalizedText(recommendation?.disposition),
      uniqueQuorumGroups: quorumGroups,
      contradictions,
      evidenceFingerprints,
      analystAttestations,
    };
    const recommendationId = addNode({
      id: projectionNodeId('recommendation', recommendationCore),
      type: 'recommendation',
      ...recommendationCore,
    });
    addEdge('applies_to', recommendationId, recommendationObservableId);
    for (const fingerprint of evidenceFingerprints) {
      const evidenceId = evidenceByFingerprint.get(fingerprint);
      if (evidenceId) addEdge('based_on', recommendationId, evidenceId);
    }
    for (const attestationId of analystAttestations) {
      const promotedId = attestationById.get(attestationId);
      if (promotedId) addEdge('corroborated_by', recommendationId, promotedId);
    }
    for (const group of quorumGroups) {
      const projectedGroup = independenceGroups.get(group);
      if (projectedGroup?.quorumEligible) addEdge('quorum_from', recommendationId, projectedGroup.id);
    }
  }

  const decisionMappings = Array.isArray(decision?.attackMappings) ? decision.attackMappings : [];
  for (const mapping of [...decisionMappings].sort((a, b) => String(a?.id ?? '').localeCompare(String(b?.id ?? '')))) {
    const node = attackNode(mapping?.id);
    if (!node) continue;
    const attackId = addNode(node);
    const fingerprints = Array.isArray(mapping?.evidenceFingerprints)
      ? [...new Set(mapping.evidenceFingerprints.map(value => String(value).toLowerCase()))].sort()
      : [];
    let linked = false;
    for (const fingerprint of fingerprints) {
      const evidenceId = evidenceByFingerprint.get(fingerprint);
      if (!evidenceId) continue;
      addEdge('mapped_to_attack', evidenceId, attackId);
      linked = true;
    }
    if (!linked) addEdge('mapped_to_attack', rootId, attackId, { basis: 'decision_mapping' });
  }

  function relationTargetNode(targetType, target) {
    if (OBSERVABLE_TYPES.has(targetType)) return observableNode(targetType, target);
    if (targetType === 'attack') return attackNode(target);
    if (targetType === 'actor') return normalizedText(target) ? actorNode(String(target)) : null;
    if (targetType === 'malware') return normalizedText(target) ? malwareNode(String(target)) : null;
    return null;
  }

  function resolveExistingSource(source, sourceType = type) {
    if (source == null || canonicalObservableValue(type, source) === canonicalObservableValue(type, indicator)) return rootId;
    const key = `${sourceType}\u0000${canonicalObservableValue(sourceType, source)}`;
    const candidates = exactValueIndex.get(key) ?? [];
    return candidates.length === 1 ? candidates[0] : null;
  }

  const orderedRelationships = [...relationships].sort((a, b) => stableJson(a).localeCompare(stableJson(b)));
  for (const relation of orderedRelationships) {
    const targetType = relationTargetType(relation);
    const target = relation?.target ?? relation?.value;
    if (!targetType || target == null || target === '') continue;
    const targetNode = relationTargetNode(targetType, target);
    if (!targetNode) continue;
    const sourceId = resolveExistingSource(relation?.source, type);
    if (!sourceId) continue;
    const targetId = addNode(targetNode);
    addEdge('related_to', sourceId, targetId, {
      relationshipType: relationshipKind(relation) ?? 'related_to',
      provider: normalizedText(relation?.provider),
    });
  }

  void correlation;

  const output = {
    schemaVersion: EVIDENCE_GRAPH_SCHEMA_VERSION,
    rootId,
    nodes: [...nodes.values()].sort((a, b) => a.type.localeCompare(b.type) || a.id.localeCompare(b.id)),
    edges: [...edges.values()].sort((a, b) => a.type.localeCompare(b.type)
      || a.source.localeCompare(b.source)
      || a.target.localeCompare(b.target)
      || stableJson(a.data).localeCompare(stableJson(b.data))
      || a.id.localeCompare(b.id)),
    counts: { nodes: nodes.size, edges: edges.size },
    truncated: false,
  };
  return deepFreeze(output);
}

export const EVIDENCE_GRAPH_LIMITS = LIMITS;
