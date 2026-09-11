import { sha256Hex } from './sha256.js';

export const EVIDENCE_GRAPH_SCHEMA_VERSION = '1.0';

const LIMITS = Object.freeze({
  nodes: 256,
  edges: 512,
  evidence: 100,
  attack: 64,
  actor: 32,
  malware: 32,
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

export function buildEvidenceGraph({
  indicator,
  type,
  evidence = [],
  relationships = [],
  correlation = {},
  decision = {},
} = {}) {
  if (!Array.isArray(evidence) || evidence.length > LIMITS.evidence) fail('evidence_graph_evidence_limit');
  if (!Array.isArray(relationships)) fail('evidence_graph_relationships_invalid');

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

  const root = observableNode(type, indicator);
  const rootId = addNode(root);
  const evidenceByFingerprint = new Map();

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
    addEdge('has_evidence', rootId, evidenceId);
    addEdge('reported_by', evidenceId, providerId);

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
