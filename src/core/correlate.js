import { isDecisivePolarity, polarity, semanticClass } from './semantics.js';

const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_RELATIONSHIPS = 100;
const MAX_CORROBORATED_FACTS = 50;
const MAX_ASSESSMENT_PROVIDERS = 25;
const MAX_LIMITATIONS = 16;
const NETWORK_TYPES = new Set(['ip', 'domain', 'url', 'asn', 'cidr']);
const STATEFUL_OBSERVATION_KINDS = new Set([
  'known_exploited', 'exploit_probability', 'vulnerability_metadata', 'vulnerability_catalog', 'open_source_vulnerability',
]);
const INFRASTRUCTURE_RELATIONSHIP_TYPES = new Set([
  'asn', 'hostname', 'domain', 'ip', 'cidr', 'netblock', 'registration', 'nameserver', 'mx',
  'resolves_to', 'cname', 'mail_exchanger', 'certificate',
]);
const THREAT_NOT_APPLICABLE_TYPES = new Set(['attack', 'cve', 'asn', 'cidr']);

function parseDate(value) {
  if (!value) return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

function freshnessClass(ageMs) {
  if (ageMs == null || ageMs < 0) return 'unknown';
  if (ageMs <= 7 * DAY_MS) return 'current';
  if (ageMs <= 30 * DAY_MS) return 'aging';
  return 'stale';
}

function observationTime(item) {
  return parseDate(item?.observation?.lastSeen) ?? parseDate(item?.observation?.firstSeen);
}

function buildFreshness(evidence, now) {
  const nowMs = parseDate(now) ?? Date.now();
  const items = evidence.map(item => {
    const rawObservedMs = observationTime(item);
    const retrievedMs = parseDate(item?.retrievedAt);
    const stateful = STATEFUL_OBSERVATION_KINDS.has(item?.observation?.kind);
    const effectiveObservedMs = stateful ? (retrievedMs ?? rawObservedMs) : rawObservedMs;
    const observationClass = freshnessClass(effectiveObservedMs == null ? null : nowMs - effectiveObservedMs);
    const retrievalClass = freshnessClass(retrievedMs == null ? null : nowMs - retrievedMs);
    return {
      provider: item.provider,
      class: observationClass,
      observationClass,
      retrievalClass,
      freshnessBasis: stateful ? 'retrieval_state' : 'observation_time',
      observedAt: effectiveObservedMs == null ? null : new Date(effectiveObservedMs).toISOString(),
      retrievedAt: retrievedMs == null ? null : new Date(retrievedMs).toISOString(),
    };
  });
  if (!items.length || items.every(item => item.observationClass === 'unknown')) return { overall: 'unknown', items };
  const ranks = { current: 0, aging: 1, stale: 2, unknown: 3 };
  const known = items.filter(item => item.observationClass !== 'unknown');
  const worst = known.sort((a, b) => ranks[b.observationClass] - ranks[a.observationClass])[0]?.observationClass ?? 'unknown';
  return { overall: worst, items };
}

function corroboration(evidence) {
  const groups = new Map();
  for (const item of evidence) {
    const cls = semanticClass(item?.observation?.kind);
    if (cls === 'attack_knowledge' || cls === 'scanner_activity' || cls === 'tor_exit' || cls === 'network_context') continue;
    const p = polarity(item?.observation?.verdict);
    if (!isDecisivePolarity(p)) continue;
    const key = `${cls}:${p}`;
    if (!groups.has(key)) groups.set(key, { semanticClass: cls, polarity: p, providers: new Set() });
    if (item?.provider) groups.get(key).providers.add(item.provider);
  }
  return [...groups.values()]
    .filter(group => group.providers.size >= 2)
    .map(group => ({ semanticClass: group.semanticClass, polarity: group.polarity, providers: [...group.providers].sort() }));
}

function contradictions(evidence) {
  const byClass = new Map();
  for (const item of evidence) {
    const cls = semanticClass(item?.observation?.kind);
    const p = polarity(item?.observation?.verdict);
    if (!isDecisivePolarity(p) || cls === 'attack_knowledge' || cls === 'scanner_activity' || cls === 'tor_exit' || cls === 'network_context') continue;
    if (!byClass.has(cls)) byClass.set(cls, { positive: new Set(), negative: new Set() });
    if (item?.provider) byClass.get(cls)[p].add(item.provider);
  }
  const output = [];
  for (const [cls, group] of byClass) {
    if (group.positive.size && group.negative.size) {
      output.push({
        semanticClass: cls,
        providers: [...new Set([...group.positive, ...group.negative])].sort(),
        positiveProviders: [...group.positive].sort(),
        negativeProviders: [...group.negative].sort(),
      });
    }
  }
  return output;
}

function evidenceQuality(evidence, freshness, contradictionItems) {
  const providerCount = new Set(evidence.map(item => item?.provider).filter(Boolean)).size;
  const counts = { current: 0, aging: 0, stale: 0, unknown: 0 };
  for (const item of freshness.items) counts[item.observationClass] = (counts[item.observationClass] ?? 0) + 1;
  const contradictionCount = contradictionItems.length;
  let level = 'none';
  if (evidence.length > 0) {
    if (providerCount >= 3 && counts.current + counts.aging >= Math.ceil(evidence.length / 2) && contradictionCount === 0) level = 'high';
    else if (providerCount >= 2 && contradictionCount <= 1) level = 'medium';
    else level = 'low';
  }
  return {
    level,
    evidenceCount: evidence.length,
    providerCount,
    currentCount: counts.current,
    agingCount: counts.aging,
    staleCount: counts.stale,
    unknownFreshnessCount: counts.unknown,
    contradictionCount,
  };
}

function threatAssessment(type, evidence) {
  if (THREAT_NOT_APPLICABLE_TYPES.has(type)) {
    return { state: 'not_applicable', assessmentBasis: { providers: [], semanticClasses: [] } };
  }
  const positive = new Set();
  const negative = new Set();
  for (const item of evidence) {
    if (semanticClass(item?.observation?.kind) !== 'reputation' || !item?.provider) continue;
    const p = polarity(item?.observation?.verdict);
    if (p === 'positive') positive.add(item.provider);
    if (p === 'negative') negative.add(item.provider);
  }
  let state = 'insufficient';
  let providers = [];
  if (positive.size && negative.size) {
    state = 'contradicted';
    providers = [...new Set([...positive, ...negative])];
  } else if (positive.size >= 2) {
    state = 'supported';
    providers = [...positive];
  } else if (negative.size && !positive.size) {
    state = 'negative';
    providers = [...negative];
  } else if (positive.size === 1) {
    providers = [...positive];
  }
  return {
    state,
    assessmentBasis: {
      providers: providers.sort().slice(0, MAX_ASSESSMENT_PROVIDERS),
      semanticClasses: providers.length ? ['reputation'] : [],
    },
  };
}

function relationshipKind(rel) {
  return rel?.type ?? rel?.relationship ?? '';
}

function infrastructureContext(type, evidence, relationships) {
  if (!NETWORK_TYPES.has(type)) return undefined;
  const providers = [...new Set(evidence
    .filter(item => semanticClass(item?.observation?.kind) === 'network_context')
    .map(item => item.provider)
    .filter(Boolean))].sort();

  const facts = new Map();
  for (const rel of relationships) {
    const kind = relationshipKind(rel);
    if (!rel?.provider || !INFRASTRUCTURE_RELATIONSHIP_TYPES.has(kind) || rel?.target == null || rel.target === '') continue;
    const key = `${kind}\u0000${String(rel.target)}`;
    if (!facts.has(key)) facts.set(key, { type: kind, target: rel.target, providers: new Set() });
    facts.get(key).providers.add(rel.provider);
  }
  const corroboratedFacts = [...facts.values()]
    .filter(item => item.providers.size >= 2)
    .map(item => ({ type: item.type, target: item.target, providers: [...item.providers].sort() }))
    .sort((a, b) => String(a.type).localeCompare(String(b.type)) || String(a.target).localeCompare(String(b.target)))
    .slice(0, MAX_CORROBORATED_FACTS);

  return { providers, corroboratedFacts };
}

function evidenceLimitations(type, evidence, freshness, threat, infra) {
  const limitations = new Set();
  if (threat.state === 'insufficient' && threat.assessmentBasis.providers.length === 1) limitations.add('single_source_threat_support');
  if (threat.state === 'contradicted') limitations.add('contradictory_threat_evidence');
  if (evidence.length && freshness.items.every(item => item.observationClass === 'stale')) limitations.add('stale_evidence_only');
  if (freshness.items.some(item => item.observationClass === 'unknown')) limitations.add('unknown_observation_time');
  const hasReputationEvidence = evidence.some(item => semanticClass(item?.observation?.kind) === 'reputation' && isDecisivePolarity(polarity(item?.observation?.verdict)));
  const hasInfrastructureEvidence = Boolean(infra?.providers?.length);
  if (NETWORK_TYPES.has(type) && hasInfrastructureEvidence && !hasReputationEvidence) limitations.add('infrastructure_only_evidence');
  return [...limitations].sort().slice(0, MAX_LIMITATIONS);
}

function huntability(type, evidence) {
  if (type === 'attack') return { level: 'medium', reason: 'behavior_or_technique_mapping' };
  if (type === 'cve') return { level: 'medium', reason: 'requires_exposure_or_behavior_telemetry' };
  if (type === 'hash') return { level: 'high', reason: 'direct_file_and_process_search' };
  if (type === 'ip' || type === 'domain' || type === 'url') {
    const hasActionable = evidence.some(item => ['reputation', 'ioc_reputation', 'threat_intelligence', 'malicious_url', 'malware_distribution', 'phishing_feed_match', 'botnet_c2'].includes(item?.observation?.kind));
    return { level: hasActionable ? 'high' : 'medium', reason: hasActionable ? 'direct_network_or_url_search' : 'contextual_network_search' };
  }
  if (type === 'asn' || type === 'cidr') return { level: 'low', reason: 'broad_network_context_requires_narrowing' };
  return { level: 'none', reason: 'no_explicit_hunt_mapping' };
}

function normalizedCvss(item) {
  const raw = item?.observation?.attributes?.cvss;
  if (Number.isFinite(Number(raw))) return { score: Number(raw), version: null, severity: null, vector: null, provider: item.provider };
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || !Number.isFinite(Number(raw.score))) return null;
  return {
    score: Number(raw.score),
    version: raw.version ?? null,
    severity: raw.severity ?? null,
    vector: raw.vector ?? null,
    provider: item.provider,
  };
}

function riskAxes(evidence) {
  const kev = evidence.find(item => item?.observation?.kind === 'known_exploited');
  const epss = evidence.find(item => item?.observation?.kind === 'exploit_probability');
  const cvss = evidence.map(normalizedCvss).find(Boolean) ?? null;
  return {
    kev: kev ? { listed: kev.observation.verdict === 'known_exploited' || kev.observation.attributes?.cataloged === true, ransomwareUse: kev.observation.attributes?.knownRansomwareCampaignUse ?? null, provider: kev.provider } : null,
    epss: epss ? { score: Number.isFinite(Number(epss.observation.attributes?.epss)) ? Number(epss.observation.attributes.epss) : null, percentile: Number.isFinite(Number(epss.observation.attributes?.percentile)) ? Number(epss.observation.attributes.percentile) : null, provider: epss.provider } : null,
    cvss,
  };
}

function dedupeRelationships(relationships) {
  const input = Array.isArray(relationships) ? relationships : [];
  const providersByTarget = new Map();
  for (const rel of input) {
    const kind = relationshipKind(rel);
    const target = rel?.target ?? rel?.value;
    const targetType = rel?.targetType ?? '';
    if (!kind || target == null || target === '' || !rel?.provider) continue;
    const key = `${kind}\u0000${String(targetType).toLowerCase()}\u0000${String(target).toLowerCase()}`;
    if (!providersByTarget.has(key)) providersByTarget.set(key, new Set());
    providersByTarget.get(key).add(rel.provider);
  }

  const seen = new Set();
  const output = [];
  for (const rel of input) {
    const kind = relationshipKind(rel);
    const target = rel?.target ?? rel?.value;
    const targetType = rel?.targetType ?? '';
    const corroborationKey = `${kind}\u0000${String(targetType).toLowerCase()}\u0000${String(target ?? '').toLowerCase()}`;
    // Modat host search returns passive/historical hostname associations. Keep
    // them in provider attributes, but do not promote a single-source hostname
    // into the shared relationship graph/hunt surface without corroboration.
    if (rel?.provider === 'modat' && kind === 'hostname' && (providersByTarget.get(corroborationKey)?.size ?? 0) < 2) continue;
    const key = [kind, rel?.source ?? '', target ?? '', rel?.provider ?? ''].join('\u0000');
    if (seen.has(key)) continue;
    seen.add(key);
    output.push(rel);
    if (output.length >= MAX_RELATIONSHIPS) break;
  }
  return output;
}

function attributionFromRelationships(relationships) {
  const actors = [...new Set(relationships.filter(rel => rel?.targetType === 'actor' || relationshipKind(rel) === 'attributed_to').map(rel => rel?.target).filter(Boolean))].sort();
  if (!actors.length) return undefined;
  return { basis: 'explicit_relationship', actors };
}

export function correlateEvidence({ indicator, type, evidence = [], relationships = [], now = new Date().toISOString() } = {}) {
  const deduped = dedupeRelationships(relationships);
  const contradictionItems = contradictions(evidence);
  const freshness = buildFreshness(evidence, now);
  const threat = threatAssessment(type, evidence);
  const infra = infrastructureContext(type, evidence, deduped);
  const output = {
    indicator,
    type,
    corroboration: corroboration(evidence),
    contradictions: contradictionItems,
    freshness,
    evidenceQuality: evidenceQuality(evidence, freshness, contradictionItems),
    threatAssessment: threat,
    limitations: evidenceLimitations(type, evidence, freshness, threat, infra),
    huntability: huntability(type, evidence),
    relationships: deduped,
  };
  if (infra) output.infrastructureContext = infra;
  if (type === 'cve') output.riskAxes = riskAxes(evidence);
  const attributionConfidence = attributionFromRelationships(deduped);
  if (attributionConfidence) output.attributionConfidence = attributionConfidence;
  return output;
}
