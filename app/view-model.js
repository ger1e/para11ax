const CONTEXT = new Set([
  'registration', 'routing', 'network_identity', 'internet_exposure',
  'scanner_activity', 'internet_noise', 'tor_exit', 'attack_knowledge',
]);
const CLAIM = new Set(['community_ioc_report', 'ransomware_post_reference', 'ransomware_victim_claim']);
const SKIPPED_FAILURES = new Set(['provider_call_budget_exhausted', 'request_deadline_exhausted', 'circuit_open']);

function labelize(value) {
  return String(value ?? 'unknown')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .toUpperCase();
}

function scalar(value) {
  if (value == null) return '—';
  if (typeof value === 'boolean') return value ? 'YES' : 'NO';
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : '—';
  if (typeof value === 'string') return value || '—';
  return null;
}

export function toFactRows(value, { limit = 24 } = {}) {
  const facts = [];
  const push = (label, item) => {
    if (facts.length >= limit) return;
    const simple = scalar(item);
    if (simple !== null) {
      facts.push({ label: labelize(label), value: simple });
      return;
    }
    if (Array.isArray(item)) {
      const simpleItems = item.map(scalar);
      if (simpleItems.every(entry => entry !== null)) {
        facts.push({ label: labelize(label), value: simpleItems.join(', ') || '—' });
        return;
      }
      item.forEach((entry, index) => push(`${label} ${index + 1}`, entry));
      return;
    }
    if (item && typeof item === 'object') {
      for (const [key, nested] of Object.entries(item)) push(label ? `${label} ${key}` : key, nested);
    }
  };

  if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const [key, item] of Object.entries(value)) push(key, item);
  } else {
    push('value', value);
  }
  return facts;
}

function riskAxis(name, value) {
  if (value == null) return { display: 'UNAVAILABLE', facts: [] };
  if (name === 'kev' && typeof value?.listed === 'boolean') {
    return { display: value.listed ? 'LISTED' : 'NOT LISTED', facts: toFactRows(value) };
  }
  if (name === 'epss' && value?.score != null) return { display: String(value.score), facts: toFactRows(value) };
  if (name === 'cvss' && value?.score != null) return { display: String(value.score), facts: toFactRows(value) };
  const facts = toFactRows(value);
  return { display: facts[0]?.value ?? 'AVAILABLE', facts };
}

function normalizedCorrelationItem(item, index, kind) {
  const source = item && typeof item === 'object' ? item : { value: item };
  const providers = Array.isArray(source.providers) ? source.providers.filter(Boolean) : [];
  const title = providers.length
    ? `${providers.join(' + ')} // ${labelize(source.kind ?? kind)}`
    : `${kind.toUpperCase()} ${index + 1}`;
  return { title, facts: toFactRows(source) };
}

function failureCopy(reason, status) {
  if (reason === 'timeout') return { label: 'UPSTREAM TIMEOUT', summary: 'Upstream provider timed out before returning evidence.' };
  if (reason === 'http_error') return { label: `UPSTREAM HTTP ${status ?? 'ERROR'}`, summary: 'Upstream provider returned an HTTP error; no evidence was inferred from the failure.' };
  if (reason === 'provider_call_budget_exhausted') return { label: 'NOT RUN / CALL BUDGET', summary: 'Provider was not called because the bounded request call budget was exhausted.' };
  if (reason === 'request_deadline_exhausted') return { label: 'NOT RUN / DEADLINE', summary: 'Provider was not run because the bounded request deadline was exhausted.' };
  if (reason === 'circuit_open') return { label: 'NOT RUN / CIRCUIT OPEN', summary: 'Provider was skipped because its bounded circuit breaker is open after recent upstream failures.' };
  if (reason === 'rate_limited') return { label: 'UPSTREAM RATE LIMITED', summary: 'Upstream provider rejected the request due to rate limiting.' };
  if (reason === 'provider_transport_error') return { label: 'UPSTREAM TRANSPORT ERROR', summary: 'Provider transport failed before a usable evidence response was received.' };
  if (reason === 'provider_error') return { label: 'UPSTREAM PROVIDER ERROR', summary: 'Provider failed without producing usable evidence.' };
  return { label: labelize(reason), summary: 'Provider did not produce usable evidence; the failure remains explicit and is not treated as negative evidence.' };
}

function normalizeFailure(failure) {
  const source = failure && typeof failure === 'object' ? failure : { reason: String(failure ?? 'unknown') };
  const reason = source.reason ?? source.error ?? 'unknown';
  const status = source.status ?? null;
  const copy = failureCopy(reason, status);
  const state = SKIPPED_FAILURES.has(reason) ? 'skipped' : 'failed';
  const details = [];
  if (status != null) details.push({ label: 'HTTP STATUS', value: String(status) });
  if (source.attempts != null) details.push({ label: 'ATTEMPTS', value: String(source.attempts) });
  if (source.retryAfter != null) details.push({ label: 'RETRY AFTER', value: String(source.retryAfter) });
  if (source.retryAfterMs != null) details.push({ label: 'RETRY AFTER', value: `${source.retryAfterMs} ms` });
  if (source.retrievedAt) details.push({ label: 'RECORDED', value: String(source.retrievedAt) });
  return {
    provider: source.provider ?? 'unknown-provider',
    state,
    reason,
    status,
    label: copy.label,
    summary: copy.summary,
    details,
  };
}

export function buildOverview(envelope) {
  const summary = envelope.providerSummary || {};
  const ok = summary.ok ?? 0;
  const failed = summary.failed ?? 0;
  const skipped = summary.skipped ?? 0;
  const coverage = `${ok} succeeded · ${failed} failed · ${skipped} not run · ${summary.cached ?? 0} cached`;
  const limitations = [];
  if (failed) limitations.push(`${failed} provider${failed === 1 ? '' : 's'} failed; treat coverage as incomplete.`);
  if (skipped) limitations.push(`${skipped} provider${skipped === 1 ? '' : 's'} did not run; absence from those sources is unknown.`);
  return {
    indicator: envelope.indicator,
    type: envelope.type,
    requestId: envelope.requestId,
    profile: envelope.profile,
    status: envelope.status,
    tone: envelope.status === 'ok' ? 'green' : envelope.status === 'partial' ? 'amber' : 'red',
    durationMs: envelope.durationMs,
    queriedAt: envelope.queriedAt ?? null,
    budget: envelope.budget || null,
    providerSummary: summary,
    coverage,
    limitations,
    freshness: envelope.correlation?.freshness || 'unknown',
    huntability: envelope.correlation?.huntability || null,
    decision: envelope.decision || null,
    guidance: envelope.guidance || null,
    intelligence: envelope.intelligence || null,
    correlationLimitations: envelope.correlation?.limitations || [],
  };
}

export function buildEvidence(envelope) {
  return (envelope.evidence || []).map((item) => {
    const kind = item.observation?.kind || 'unknown';
    const semanticClass = CONTEXT.has(kind) ? 'context' : CLAIM.has(kind) || item.provider === 'otx' || item.provider === 'abuseipdb' ? 'claim' : 'evidence';
    return {
      provider: item.provider,
      kind,
      verdict: item.observation?.verdict ?? null,
      semanticClass,
      semanticNote: semanticClass === 'claim' ? 'Reported/claimed evidence; not proof of compromise.' : '',
      confidence: item.observation?.confidence ?? null,
      firstSeen: item.observation?.firstSeen ?? null,
      lastSeen: item.observation?.lastSeen ?? null,
      attributeFacts: toFactRows(item.observation?.attributes ?? {}, { limit: 96 }),
      tags: (item.observation?.tags ?? []).map(value => scalar(value) ?? String(value)),
      malwareFamily: item.observation?.malwareFamily ?? null,
      actorFacts: item.observation?.actor ? toFactRows(item.observation.actor) : [],
      references: item.references ?? [],
      cacheState: item.cacheState ?? null,
      retrievedAt: item.retrievedAt ?? null,
      parserVersion: item.integrity?.parserVersion ?? null,
      fingerprint: item.integrity?.fingerprint ?? null,
    };
  });
}

export function buildCorrelation(envelope) {
  const correlation = envelope.correlation || {};
  return {
    corroboration: (correlation.corroboration || []).map((item, index) => normalizedCorrelationItem(item, index, 'corroboration')),
    contradictions: (correlation.contradictions || []).map((item, index) => normalizedCorrelationItem(item, index, 'contradiction')),
    freshness: correlation.freshness || 'unknown',
    evidenceQuality: correlation.evidenceQuality || null,
    threatAssessment: correlation.threatAssessment || null,
    limitations: correlation.limitations || [],
    infrastructureContext: correlation.infrastructureContext || null,
    huntability: correlation.huntability || null,
    riskAxes: {
      kev: riskAxis('kev', correlation.riskAxes?.kev ?? null),
      epss: riskAxis('epss', correlation.riskAxes?.epss ?? null),
      cvss: riskAxis('cvss', correlation.riskAxes?.cvss ?? null),
    },
    attributionConfidence: correlation.attributionConfidence ?? null,
  };
}

export function buildRelationships(envelope) {
  return (envelope.relationships || envelope.correlation?.relationships || []).map((item, index) => ({
    title: `RELATIONSHIP ${index + 1}`,
    facts: toFactRows(item),
  }));
}

export function buildCoverage(envelope) {
  const summary = envelope.providerSummary || {};
  const ok = summary.ok ?? 0;
  const failed = summary.failed ?? 0;
  const skipped = summary.skipped ?? 0;
  const cached = summary.cached ?? 0;
  return {
    failures: (envelope.failures || []).map(normalizeFailure),
    summary,
    summaryText: `${ok} succeeded · ${failed} failed · ${skipped} not run · ${cached} cached`,
  };
}

const IP_SECTION_DEFS = Object.freeze([
  Object.freeze({ id: 'identity', title: 'IDENTITY & ASN' }),
  Object.freeze({ id: 'registration-routing', title: 'REGISTRATION / ROUTING' }),
  Object.freeze({ id: 'geo-network', title: 'GEO / NETWORK CONTEXT' }),
  Object.freeze({ id: 'exposure', title: 'EXPOSURE & SERVICES' }),
  Object.freeze({ id: 'reputation-abuse', title: 'REPUTATION / ABUSE' }),
  Object.freeze({ id: 'malware-c2-ransomware', title: 'MALWARE / C2 / RANSOMWARE' }),
  Object.freeze({ id: 'tor-scanner', title: 'TOR / SCANNER ACTIVITY' }),
  Object.freeze({ id: 'related-infrastructure', title: 'RELATED INFRASTRUCTURE' }),
  Object.freeze({ id: 'correlation', title: 'CORROBORATION / CONTRADICTIONS' }),
  Object.freeze({ id: 'temporal-context', title: 'TEMPORAL CONTEXT' }),
  Object.freeze({ id: 'attack-behavior', title: 'ATT&CK / BEHAVIOR' }),
  Object.freeze({ id: 'analyst-actions', title: 'ANALYST NEXT ACTIONS' }),
  Object.freeze({ id: 'huntability', title: 'HUNTABILITY' }),
  Object.freeze({ id: 'coverage', title: 'COVERAGE / LIMITATIONS' }),
]);

const IP_SECTION_KINDS = Object.freeze({
  identity: new Set(['network_identity', 'routing']),
  'registration-routing': new Set(['registration', 'routing']),
  exposure: new Set(['internet_exposure']),
  'reputation-abuse': new Set(['reputation', 'abuse_reports', 'drop_netblock', 'community_ioc_report', 'web_intelligence']),
  'malware-c2-ransomware': new Set(['botnet_c2', 'malware_association', 'threat_context', 'misp_feed_hit', 'ransomware_post_reference', 'ransomware_victim_claim']),
  'tor-scanner': new Set(['tor_exit', 'scanner_activity', 'internet_noise']),
});

const IP_SECTION_FACT_LABELS = Object.freeze({
  identity: /^(IP|ASN|ORGANIZATION|AS NAME|ASNAME|HOLDER|DOMAIN)$/,
  'registration-routing': /^(PREFIX|CIDR|CIDR0(?: .*)?|NETWORK|HANDLE|NAME|START ADDRESS|END ADDRESS|START AUTNUM|END AUTNUM|ANNOUNCED|ASNS|BLOCK(?: .*)?)$/,
  'geo-network': /^(COUNTRY|CONTINENT|CITY|REGION|LOCATION|LATITUDE|LONGITUDE|TIMEZONE)$/,
  exposure: /(PORT|SERVICE|HOSTNAME|PROTOCOL|BANNER|PRODUCT|VERSION|CERT|TLS|HTTP|SSH|DNS)/,
  'reputation-abuse': /(ABUSE|REPORT|CLASSIFICATION|LISTED|RISK|SCORE|MALICIOUS|SUSPICIOUS|REPUTATION|CATEGORY|USAGE|ISP)/,
  'malware-c2-ransomware': /(MALWARE|BOTNET|C2|FAMILY|IOC|CAMPAIGN|ACTOR|THREAT|RANSOM|SIGNATURE|TAGS?)/,
  'tor-scanner': /(TOR|NOISE|RIOT|CLASSIFICATION|ATTACK|REPORT|SCANNER|LAST SEEN|FIRST SEEN)/,
});

const IP_THREAT_KINDS = new Set([
  'reputation', 'abuse_reports', 'drop_netblock', 'community_ioc_report', 'botnet_c2',
  'malware_association', 'threat_context', 'misp_feed_hit', 'ransomware_post_reference',
  'ransomware_victim_claim', 'internet_noise',
]);
const IP_POSITIVE_VERDICTS = new Set(['malicious', 'observed', 'listed', 'suspicious', 'abusive', 'malware', 'botnet', 'c2']);
const IP_NO_RESULT_VERDICTS = new Set(['no_result']);

function meaningfulFact(fact) {
  const value = String(fact?.value ?? '').trim();
  return value && value !== '—' && value.toLowerCase() !== 'null' && value.toLowerCase() !== 'undefined';
}

function sourcedFacts(cards, sectionId, limit = 40) {
  const matcher = IP_SECTION_FACT_LABELS[sectionId];
  if (!matcher) return [];
  const allowedKinds = IP_SECTION_KINDS[sectionId] ?? null;
  const merged = new Map();
  for (const card of cards) {
    if (allowedKinds && !allowedKinds.has(card.kind)) continue;
    for (const fact of card.attributeFacts || []) {
      if (!matcher.test(fact.label) || !meaningfulFact(fact)) continue;
      const key = `${fact.label}\u0000${fact.value}`;
      const current = merged.get(key) ?? { label: fact.label, value: String(fact.value), sources: new Set() };
      if (card.provider) current.sources.add(card.provider);
      merged.set(key, current);
    }
  }
  return [...merged.values()]
    .map(fact => ({ ...fact, sources: [...fact.sources].sort((a, b) => a.localeCompare(b)) }))
    .sort((a, b) => a.label.localeCompare(b.label) || a.value.localeCompare(b.value))
    .slice(0, limit);
}

function reportItem(card) {
  const facts = [];
  if (card.confidence !== null) facts.push({ label: 'CONFIDENCE', value: String(card.confidence) });
  if (card.firstSeen) facts.push({ label: 'FIRST SEEN', value: card.firstSeen });
  if (card.lastSeen) facts.push({ label: 'LAST SEEN', value: card.lastSeen });
  if (card.malwareFamily) facts.push({ label: 'MALWARE', value: card.malwareFamily });
  if (card.tags?.length) facts.push({ label: 'TAGS', value: card.tags.join(', ') });
  return {
    provider: card.provider,
    kind: labelize(card.kind),
    verdict: labelize(card.verdict ?? 'unknown'),
    semanticClass: card.semanticClass,
    semanticNote: card.semanticNote,
    facts,
  };
}

function reportItems(cards, kinds) {
  return cards
    .filter(card => kinds.has(card.kind) && !IP_NO_RESULT_VERDICTS.has(String(card.verdict ?? '').toLowerCase()))
    .map(reportItem)
    .slice(0, 32);
}

function humanizeToken(value) {
  return String(value ?? '').replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim().toLowerCase();
}

function humanizeList(values) {
  return [...new Set((Array.isArray(values) ? values : []).filter(value => value !== null && value !== undefined && String(value).trim()).map(humanizeToken))].join(', ');
}

function freshnessDisplay(value) {
  if (typeof value === 'string') return labelize(value);
  if (value && typeof value === 'object' && value.overall) return labelize(value.overall);
  return 'UNKNOWN';
}

function isCompatibleIpIntelligence(intelligence) {
  return Boolean(
    intelligence &&
    intelligence.schemaVersion === '1.0' &&
    intelligence.type === 'ip' &&
    intelligence.policy?.type === 'ip' &&
    intelligence.policy?.version === '1.0' &&
    intelligence.evidenceStrength &&
    intelligence.analystPriority &&
    intelligence.threatContext,
  );
}

function kernelProviders(items) {
  return [...new Set((Array.isArray(items) ? items : []).map(item => item?.provider).filter(Boolean))].sort((a, b) => a.localeCompare(b));
}

function kernelRelationshipItems(intelligence) {
  if (!isCompatibleIpIntelligence(intelligence)) return [];
  const relationships = (Array.isArray(intelligence.relationshipValue) ? intelligence.relationshipValue : []).slice(0, 32).map((item, index) => ({
    title: `${labelize(item?.class ?? 'related')} RELATIONSHIP // ${labelize(item?.targetType ?? item?.type ?? 'entity')}`,
    facts: [
      { label: 'RELATIONSHIP ID', value: String(item?.id ?? `relationship-${index + 1}`) },
      { label: 'TYPE', value: humanizeToken(item?.type) || 'related to' },
      { label: 'TARGET TYPE', value: labelize(item?.targetType ?? 'unknown') },
      { label: 'TARGET', value: String(item?.target ?? '—') },
      { label: 'PROVIDER', value: String(item?.provider ?? 'unknown') },
      { label: 'EVIDENCE LINKS', value: String(item?.evidenceFingerprints?.length ?? 0) },
      { label: 'RULE', value: humanizeToken(item?.ruleId) || 'none emitted' },
    ],
  }));
  const pivots = (Array.isArray(intelligence.pivotCandidates) ? intelligence.pivotCandidates : []).slice(0, 16).map((item, index) => ({
    title: `${labelize(item?.priority ?? 'low')} PIVOT // ${labelize(item?.targetType ?? 'entity')}`,
    facts: [
      { label: 'RELATIONSHIP ID', value: String(item?.relationshipId ?? `pivot-${index + 1}`) },
      { label: 'TARGET TYPE', value: labelize(item?.targetType ?? 'unknown') },
      { label: 'TARGET', value: String(item?.target ?? '—') },
      { label: 'PROVIDER', value: String(item?.provider ?? 'unknown') },
      { label: 'EVIDENCE LINKS', value: String(item?.evidenceFingerprints?.length ?? 0) },
      { label: 'RULE', value: humanizeToken(item?.ruleId) || 'none emitted' },
    ],
  }));
  return [...relationships, ...pivots].slice(0, 48);
}

function kernelCorrelationItems(intelligence) {
  if (!isCompatibleIpIntelligence(intelligence)) return [];
  const corroboration = (Array.isArray(intelligence.corroboration) ? intelligence.corroboration : []).slice(0, 24).map((item, index) => ({
    title: `${labelize(item?.independence ?? 'unknown')} // ${labelize(item?.semanticClass ?? item?.category ?? `corroboration ${index + 1}`)}`,
    tone: 'corroboration',
    facts: [
      { label: 'INDEPENDENCE', value: labelize(item?.independence ?? 'unknown') },
      { label: 'POLARITY', value: labelize(item?.polarity ?? 'unknown') },
      { label: 'PROVIDERS', value: (item?.providers || []).join(', ') || 'none emitted' },
      { label: 'SOURCE ROLES', value: humanizeList(item?.sourceRoles) || 'none emitted' },
      { label: 'EVIDENCE LINKS', value: String(item?.evidenceFingerprints?.length ?? 0) },
    ],
  }));
  const contradictions = (Array.isArray(intelligence.contradiction?.items) ? intelligence.contradiction.items : []).slice(0, 8).map((item, index) => ({
    title: `CONTRADICTION ${index + 1} // ${labelize(item?.semanticClass ?? item?.category ?? 'unknown')}`,
    tone: 'contradiction',
    facts: [
      { label: 'SEVERITY', value: labelize(intelligence.contradiction?.level ?? 'none') },
      { label: 'PROVIDERS', value: (item?.providers || []).join(', ') || 'none emitted' },
      { label: 'EVIDENCE LINKS', value: String(item?.evidenceFingerprints?.length ?? 0) },
    ],
  }));
  return [...corroboration, ...contradictions].slice(0, 32);
}

function temporalFacts(decision, cards, intelligence = null) {
  const kernelTemporal = isCompatibleIpIntelligence(intelligence) ? intelligence.temporalRelevance : null;
  const temporal = kernelTemporal || decision?.temporal || null;
  const firstSeen = temporal?.firstSeen ?? cards.map(card => card.firstSeen).filter(Boolean).sort()[0] ?? null;
  const lastSeen = temporal?.lastSeen ?? cards.map(card => card.lastSeen).filter(Boolean).sort().at(-1) ?? null;
  const facts = [];
  if (kernelTemporal) facts.push({ label: 'TEMPORAL STATE', value: labelize(kernelTemporal.overall ?? 'unknown') });
  if (firstSeen) facts.push({ label: 'FIRST SEEN', value: firstSeen });
  if (lastSeen) facts.push({ label: 'LAST SEEN', value: lastSeen });
  if (temporal?.ageDays != null) facts.push({ label: 'AGE', value: `${temporal.ageDays} day${temporal.ageDays === 1 ? '' : 's'}` });
  if (temporal?.activeSpanDays != null) facts.push({ label: 'ACTIVE SPAN', value: `${temporal.activeSpanDays} day${temporal.activeSpanDays === 1 ? '' : 's'}` });
  if (kernelTemporal?.distribution) {
    facts.push({ label: 'CURRENT', value: String(kernelTemporal.distribution.current ?? 0) });
    facts.push({ label: 'AGING', value: String(kernelTemporal.distribution.aging ?? 0) });
    facts.push({ label: 'STALE', value: String(kernelTemporal.distribution.stale ?? 0) });
    facts.push({ label: 'UNKNOWN TIME', value: String(kernelTemporal.distribution.unknown ?? 0) });
  }
  return facts;
}

function attackItems(decision, guidance) {
  const mappings = decision?.attackMappings?.length ? decision.attackMappings : (guidance?.attackMappings || []);
  return mappings.slice(0, 32).map(mapping => ({
    title: String(mapping.id || 'ATT&CK MAPPING').toUpperCase(),
    facts: [
      { label: 'BASIS', value: humanizeList(mapping.bases) || 'unknown' },
      { label: 'PROVIDERS', value: (mapping.providers || []).join(', ') || 'none' },
      { label: 'EVIDENCE LINKS', value: String(mapping.evidenceFingerprints?.length ?? 0) },
    ],
  }));
}

function actionItems(decision, guidance) {
  const hunts = decision?.huntPlan?.length ? decision.huntPlan : (guidance?.hunts || []);
  return hunts.slice(0, 8).map(hunt => ({
    title: `${labelize(hunt.priority ?? 'medium')} // ${labelize(hunt.id ?? 'hunt')}`,
    facts: [
      { label: 'HYPOTHESIS', value: hunt.hypothesis ?? 'No explicit hypothesis emitted.' },
      { label: 'TELEMETRY', value: (hunt.telemetry || []).join(', ') || 'none specified' },
    ],
    detailFacts: [
      { label: 'FALSE POSITIVES', value: humanizeList(hunt.falsePositives) || 'none specified' },
      { label: 'TUNING', value: humanizeList(hunt.tuning) || 'none specified' },
      { label: 'EVIDENCE LINKS', value: String(hunt.evidenceFingerprints?.length ?? 0) },
      ...(hunt.kql ? [{ label: 'KQL', value: hunt.kql }] : []),
    ],
  }));
}

function firstFact(sections, label) {
  for (const section of sections) {
    const fact = section.facts?.find(item => item.label === label && meaningfulFact(item));
    if (fact) return fact.value;
  }
  return null;
}

function buildIpAssessment({ overview, evidence, correlation, sections, intelligence = null }) {
  const decision = overview.decision || null;
  const threatBasis = correlation?.threatAssessment?.assessmentBasis?.providers || [];
  const threatProviders = new Set(threatBasis);
  if (!threatProviders.size) {
    for (const card of evidence) {
      const verdict = String(card.verdict ?? '').toLowerCase();
      if (IP_THREAT_KINDS.has(card.kind) && IP_POSITIVE_VERDICTS.has(verdict) && card.provider) threatProviders.add(card.provider);
    }
  }
  const exposureProviders = new Set(evidence.filter(card => card.kind === 'internet_exposure' && !IP_NO_RESULT_VERDICTS.has(String(card.verdict ?? '').toLowerCase())).map(card => card.provider).filter(Boolean));
  const asn = firstFact(sections, 'ASN');
  const organization = firstFact(sections, 'ORGANIZATION') ?? firstFact(sections, 'AS NAME') ?? firstFact(sections, 'ASNAME') ?? firstFact(sections, 'HOLDER');
  const identity = [asn, organization].filter(Boolean).join(' / ');
  const subject = identity ? `${overview.indicator} is associated with ${identity}.` : `${overview.indicator} was enriched as an IP observable.`;

  if (isCompatibleIpIntelligence(intelligence)) {
    const state = labelize(decision?.disposition ?? intelligence.analystPriority?.level ?? 'unknown');
    const confidence = labelize(decision?.confidence ?? decision?.assessment?.confidence ?? 'unknown');
    const priority = labelize(intelligence.analystPriority?.level ?? 'insufficient');
    const strength = labelize(intelligence.evidenceStrength?.level ?? 'none');
    const threatState = labelize(intelligence.threatContext?.state ?? 'insufficient');
    const freshness = labelize(intelligence.temporalRelevance?.overall ?? 'unknown');
    const huntability = labelize(intelligence.huntRelevance?.level ?? 'none');
    const directBasis = kernelProviders(intelligence.threatContext?.direct);
    const supportingBasis = kernelProviders(intelligence.threatContext?.supporting);
    const reasons = decision?.reasons?.length ? decision.reasons : (intelligence.analystPriority?.reasons || []);
    const decisionSource = `INTELLIGENCE KERNEL V${intelligence.schemaVersion} / DECISION SUPPORT V${decision?.version || '1.0'}`;
    return {
      state,
      confidence,
      decisionSource,
      summary: `${subject} Intelligence Kernel v${intelligence.schemaVersion} sets analyst priority ${priority} with ${strength} evidence strength and threat state ${threatState}. Decision support recommends ${state} with ${confidence} confidence. Direct basis: ${directBasis.join(' + ') || 'none emitted'}. Supporting basis: ${supportingBasis.join(' + ') || 'none emitted'}. Freshness is ${freshness}; hunt relevance is ${huntability}; coverage impact is ${labelize(intelligence.coverageImpact?.level ?? 'none')}. Failed or absent sources remain unknown rather than benign.`,
      facts: [
        { label: 'DECISION SOURCE', value: decisionSource },
        { label: 'DISPOSITION', value: state },
        { label: 'CONFIDENCE', value: confidence },
        { label: 'ANALYST PRIORITY', value: priority },
        { label: 'EVIDENCE STRENGTH', value: strength },
        { label: 'THREAT STATE', value: threatState },
        { label: 'DIRECT BASIS', value: directBasis.join(', ') || 'NONE EMITTED' },
        { label: 'SUPPORTING BASIS', value: supportingBasis.join(', ') || 'NONE EMITTED' },
        { label: 'KERNEL VERSION', value: intelligence.schemaVersion },
        { label: 'POLICY VERSION', value: String(intelligence.policy?.version ?? 'unknown') },
        { label: 'FRESHNESS', value: freshness },
        { label: 'HUNTABILITY', value: huntability },
        { label: 'PRIORITY BASIS', value: humanizeList(intelligence.analystPriority?.reasons) || 'none emitted' },
        { label: 'STRENGTH BASIS', value: humanizeList(intelligence.evidenceStrength?.reasons) || 'none emitted' },
        { label: 'KEY LIMITATIONS', value: humanizeList(intelligence.limitations) || 'none emitted' },
        { label: 'DECISION REASONS', value: humanizeList(reasons) || 'none emitted' },
        { label: 'EXPOSURE SOURCES', value: exposureProviders.size ? [...exposureProviders].sort().join(', ') : 'NONE OBSERVED' },
      ],
    };
  }

  if (decision?.disposition) {
    const state = labelize(decision.disposition);
    const confidence = labelize(decision.confidence ?? decision.assessment?.confidence ?? 'unknown');
    const threatState = labelize(decision.assessment?.threatState ?? correlation?.threatAssessment?.state ?? 'insufficient');
    const evidenceQuality = labelize(decision.assessment?.evidenceQuality ?? correlation?.evidenceQuality?.level ?? 'none');
    const freshness = labelize(decision.assessment?.freshness ?? freshnessDisplay(correlation?.freshness));
    const huntability = labelize(decision.assessment?.huntability ?? correlation?.huntability?.level ?? 'none');
    const reasons = decision.reasons?.length ? decision.reasons : (decision.assessment?.reasons || []);
    const basis = threatBasis.length ? threatBasis.join(' + ') : 'no independent reputation basis emitted';
    return {
      state,
      confidence,
      decisionSource: `DECISION SUPPORT V${decision.version || '1.0'}`,
      summary: `${subject} Decision support recommends ${state} with ${confidence} confidence. Threat state is ${threatState}${threatBasis.length ? ` across ${basis}` : ''}. Evidence quality is ${evidenceQuality} and freshness is ${freshness}. Coverage: ${overview.coverage}. Failed or absent sources remain unknown rather than benign.`,
      facts: [
        { label: 'DECISION SOURCE', value: `DECISION SUPPORT V${decision.version || '1.0'}` },
        { label: 'DISPOSITION', value: state },
        { label: 'CONFIDENCE', value: confidence },
        { label: 'THREAT STATE', value: threatState },
        { label: 'THREAT BASIS', value: threatBasis.length ? threatBasis.join(', ') : 'NONE EMITTED' },
        { label: 'EVIDENCE QUALITY', value: evidenceQuality },
        { label: 'FRESHNESS', value: freshness },
        { label: 'HUNTABILITY', value: huntability },
        { label: 'DECISION REASONS', value: humanizeList(reasons) || 'none emitted' },
        { label: 'EXPOSURE SOURCES', value: exposureProviders.size ? [...exposureProviders].sort().join(', ') : 'NONE OBSERVED' },
      ],
    };
  }

  const corroborated = correlation.corroboration?.length ?? 0;
  const threatCount = threatProviders.size;
  const state = threatCount >= 2 ? 'ACTIONABLE THREAT EVIDENCE' : threatCount === 1 ? 'SINGLE-SOURCE THREAT SIGNAL' : 'NO ACTIONABLE THREAT EVIDENCE OBSERVED';
  const confidence = threatCount >= 3 || (threatCount >= 2 && corroborated > 0) ? 'HIGH' : threatCount >= 2 ? 'MEDIUM' : threatCount === 1 ? 'LOW' : 'INFORMATIONAL';
  const threatSentence = threatCount
    ? `${threatCount} independent provider${threatCount === 1 ? '' : 's'} reported threat-relevant observations.`
    : 'No provider returned a threat-relevant positive observation; this is not a benign verdict.';
  const exposureSentence = exposureProviders.size
    ? `${exposureProviders.size} provider${exposureProviders.size === 1 ? '' : 's'} returned exposure/service context.`
    : 'No exposure/service context was returned.';
  return {
    state,
    confidence,
    decisionSource: 'REPORT FALLBACK',
    summary: `${subject} ${threatSentence} ${exposureSentence} Coverage: ${overview.coverage}. Failed or absent sources remain unknown rather than benign.`,
    facts: [
      { label: 'DISPOSITION', value: state },
      { label: 'CONFIDENCE', value: confidence },
      { label: 'THREAT SIGNAL SOURCES', value: threatProviders.size ? [...threatProviders].sort().join(', ') : 'NONE OBSERVED' },
      { label: 'EXPOSURE SOURCES', value: exposureProviders.size ? [...exposureProviders].sort().join(', ') : 'NONE OBSERVED' },
      { label: 'HUNTABILITY', value: correlation.huntability?.level ? labelize(correlation.huntability.level) : 'UNKNOWN' },
    ],
  };
}

export function buildIpAnalystReport({ overview, evidence, correlation, relationships, coverage }) {
  if (!overview || overview.type !== 'ip') throw new TypeError('IP report requires an IP overview');
  const cards = Array.isArray(evidence) ? evidence : [];
  const decision = overview.decision || null;
  const guidance = overview.guidance || null;
  const intelligence = isCompatibleIpIntelligence(overview.intelligence) ? overview.intelligence : null;
  const sections = IP_SECTION_DEFS.map(definition => ({ id: definition.id, title: definition.title, facts: [], items: [] }));
  const byId = new Map(sections.map(section => [section.id, section]));

  for (const id of ['identity', 'registration-routing', 'geo-network', 'exposure', 'reputation-abuse', 'malware-c2-ransomware', 'tor-scanner']) {
    byId.get(id).facts = sourcedFacts(cards, id);
  }
  for (const [id, kinds] of Object.entries(IP_SECTION_KINDS)) byId.get(id).items = reportItems(cards, kinds);

  const kernelRelationships = kernelRelationshipItems(intelligence);
  byId.get('related-infrastructure').items = kernelRelationships.length ? kernelRelationships : (relationships || []).slice(0, 64);
  const quality = correlation?.evidenceQuality || {};
  const threat = correlation?.threatAssessment || {};
  const threatProviders = threat?.assessmentBasis?.providers || [];
  const temporalDistribution = intelligence?.temporalRelevance?.distribution || null;
  byId.get('correlation').facts = [
    { label: 'FRESHNESS', value: intelligence ? labelize(intelligence.temporalRelevance?.overall ?? 'unknown') : freshnessDisplay(correlation?.freshness) },
    { label: 'THREAT STATE', value: intelligence ? labelize(intelligence.threatContext?.state ?? 'unknown') : labelize(threat?.state ?? decision?.assessment?.threatState ?? 'unknown') },
    { label: 'THREAT BASIS', value: intelligence ? (kernelProviders(intelligence.threatContext?.direct).join(', ') || 'NONE EMITTED') : (threatProviders.length ? threatProviders.join(', ') : 'NONE EMITTED') },
    { label: 'EVIDENCE QUALITY', value: intelligence ? labelize(intelligence.evidenceStrength?.level ?? 'none') : labelize(quality?.level ?? decision?.assessment?.evidenceQuality ?? 'none') },
    { label: 'EVIDENCE ITEMS', value: String(quality?.evidenceCount ?? cards.length) },
    { label: 'EVIDENCE PROVIDERS', value: String(intelligence?.sourceDiversity?.providerCount ?? quality?.providerCount ?? new Set(cards.map(card => card.provider).filter(Boolean)).size) },
    { label: 'CURRENT / AGING / STALE / UNKNOWN', value: temporalDistribution ? `${temporalDistribution.current ?? 0} / ${temporalDistribution.aging ?? 0} / ${temporalDistribution.stale ?? 0} / ${temporalDistribution.unknown ?? 0}` : `${quality?.currentCount ?? 0} / ${quality?.agingCount ?? 0} / ${quality?.staleCount ?? 0} / ${quality?.unknownFreshnessCount ?? 0}` },
    { label: 'CORROBORATION GROUPS', value: String(intelligence?.corroboration?.length ?? correlation?.corroboration?.length ?? 0) },
    { label: 'CONTRADICTIONS', value: String(intelligence?.contradiction?.items?.length ?? correlation?.contradictions?.length ?? 0) },
    ...(intelligence ? [{ label: 'CONTRADICTION SEVERITY', value: labelize(intelligence.contradiction?.level ?? 'none') }] : []),
  ];
  const kernelCorrelation = kernelCorrelationItems(intelligence);
  byId.get('correlation').items = kernelCorrelation.length ? kernelCorrelation : [
    ...(correlation?.corroboration || []).map(item => ({ ...item, tone: 'corroboration' })),
    ...(correlation?.contradictions || []).map(item => ({ ...item, tone: 'contradiction' })),
  ].slice(0, 32);

  byId.get('temporal-context').facts = temporalFacts(decision, cards, intelligence);
  byId.get('attack-behavior').items = attackItems(decision, guidance);
  byId.get('analyst-actions').items = actionItems(decision, guidance);
  byId.get('analyst-actions').facts = intelligence ? [
    { label: 'KERNEL HUNT RELEVANCE', value: labelize(intelligence.huntRelevance?.level ?? 'none') },
    { label: 'ANALYST PRIORITY', value: labelize(intelligence.analystPriority?.level ?? 'insufficient') },
    { label: 'PRIORITY BASIS', value: humanizeList(intelligence.analystPriority?.reasons) || 'none emitted' },
    { label: 'HUNT BASIS', value: humanizeList(intelligence.huntRelevance?.ruleIds) || 'none emitted' },
  ] : [];
  byId.get('analyst-actions').summary = byId.get('analyst-actions').items.length
    ? intelligence
      ? 'Decision/Guidance hunt instructions remain authoritative; Intelligence Kernel context annotates hunt relevance and priority basis without generating browser-side KQL.'
      : 'Prioritized deterministic hunt guidance derived from existing Decision/Guidance output; validate telemetry availability before execution.'
    : 'No deterministic hunt plan was emitted for this result.';

  byId.get('huntability').facts = [
    { label: 'LEVEL', value: labelize(intelligence?.huntRelevance?.level ?? correlation?.huntability?.level ?? decision?.assessment?.huntability ?? 'unknown') },
    ...(intelligence ? [
      { label: 'KERNEL DIRECT SEARCH', value: intelligence.huntRelevance?.directSearch === true ? 'YES' : 'NO' },
      { label: 'KERNEL PIVOTS', value: String(intelligence.huntRelevance?.pivotCount ?? 0) },
    ] : []),
    { label: 'RATIONALE', value: correlation?.huntability?.rationale ?? (humanizeToken(correlation?.huntability?.reason) || 'No huntability rationale emitted.') },
    { label: 'TELEMETRY READINESS', value: labelize(decision?.telemetry?.status ?? guidance?.telemetry?.status ?? 'unknown') },
    { label: 'REQUIRED TABLES', value: (decision?.telemetry?.requiredTables ?? guidance?.telemetry?.requiredTables ?? []).join(', ') || 'none specified' },
    { label: 'ENVIRONMENT VALIDATED', value: (decision?.telemetry?.environmentValidated ?? guidance?.telemetry?.environmentValidated) === true ? 'YES' : 'NO' },
  ];

  const limitationValues = [...new Set([
    ...(overview.limitations || []),
    ...(overview.correlationLimitations || []),
    ...(correlation?.limitations || []),
    ...(guidance?.limitations || []),
    ...(intelligence?.limitations || []),
  ].filter(Boolean).map(value => String(value).includes(' ') ? String(value) : humanizeToken(value)))];
  byId.get('coverage').summary = coverage?.summaryText ?? overview.coverage;
  byId.get('coverage').failures = (coverage?.failures || []).slice(0, 32);
  byId.get('coverage').facts = [
    ...(intelligence ? [
      { label: 'COVERAGE IMPACT', value: labelize(intelligence.coverageImpact?.level ?? 'none') },
      { label: 'UNIQUE CAPABILITY LOSS', value: humanizeList(intelligence.coverageImpact?.uniqueCapabilityLoss) || 'NONE' },
      { label: 'DUPLICATE COVERAGE LOSS', value: humanizeList(intelligence.coverageImpact?.duplicateCoverageLoss) || 'NONE' },
    ] : []),
    ...limitationValues.map((value, index) => ({ label: `LIMITATION ${index + 1}`, value })),
  ];

  const communityFacts = cards.flatMap(card => (card.attributeFacts || [])
    .filter(fact => /^COMMUNITY /.test(fact.label) && meaningfulFact(fact))
    .map(fact => ({ ...fact, sources: [card.provider] })));
  if (communityFacts.length) sections.push({ id: 'community-context', title: 'COMMUNITY CONTEXT / UNVERIFIED', summary: 'Source-reported community claims are not independent evidence or confirmed malware attribution. Coverage is limited to returned records.', facts: communityFacts, items: [] });
  const additionalFacts = cards.flatMap(card => (card.attributeFacts || [])
    .filter(fact => /^(REPORTED MALWARE FAMILIES|CONFLICTING FAMILY LABELS|REPORTED ASSOCIATIONS|OMITTED ASSOCIATIONS|VENDOR SUGGESTED THREAT LABEL|VENDOR POPULAR THREAT)/.test(fact.label) && meaningfulFact(fact))
    .map(fact => ({ ...fact, sources: [card.provider] })));
  if (additionalFacts.length) sections.push({ id: 'reported-classifications', title: 'SOURCE-REPORTED CLASSIFICATIONS', summary: 'Provider and engine labels may differ; they are not independent attribution confirmations.', facts: additionalFacts, items: [] });
  const sourceUrls = [...new Set(cards.flatMap(card => card.references || []).filter(value => typeof value === 'string' && /^https?:\/\//i.test(value)))].sort();
  if (sourceUrls.length) sections.push({ id: 'source-references', title: 'SOURCE REFERENCES', facts: sourceUrls.map((value, index) => ({ label: 'SOURCE ' + (index + 1), value })), items: [] });
  const assessment = buildIpAssessment({ overview, evidence: cards, correlation: correlation || {}, sections, intelligence });
  return {
    title: `IP INTELLIGENCE REPORT // ${overview.indicator}`,
    indicator: overview.indicator,
    status: overview.status,
    profile: overview.profile,
    durationMs: overview.durationMs,
    intelligence,
    assessment,
    sections,
  };
}

function textFact(fact, prefix = '') {
  const sources = fact?.sources?.length ? ` [${fact.sources.join(' + ')}]` : '';
  return `${prefix}${fact?.label ?? 'FACT'}: ${fact?.value ?? '—'}${sources}`;
}

function textSection(title, lines) {
  const body = lines.filter(Boolean);
  return [title, '-'.repeat(title.length), ...(body.length ? body : ['No reportable observations.']), ''];
}

export function renderIpAnalystReportText(report) {
  if (!report || typeof report !== 'object' || !String(report.title || '').startsWith('IP INTELLIGENCE REPORT //')) {
    throw new TypeError('valid IP analyst report required');
  }
  const out = [
    report.title,
    `STATUS: ${labelize(report.status ?? 'unknown')}`,
    `PROFILE: ${labelize(report.profile ?? 'unknown')}`,
    `DURATION: ${report.durationMs == null ? '—' : `${report.durationMs} ms`}`,
    '',
    ...textSection('EXECUTIVE ASSESSMENT', [
      `DISPOSITION: ${report.assessment?.state ?? 'UNKNOWN'}`,
      `CONFIDENCE: ${report.assessment?.confidence ?? 'UNKNOWN'}`,
      report.assessment?.summary ?? '',
      ...(report.assessment?.facts || []).filter(fact => !['DISPOSITION', 'CONFIDENCE'].includes(fact.label)).map(fact => textFact(fact)),
    ]),
  ];

  for (const section of report.sections || []) {
    const lines = [];
    if (section.summary) lines.push(section.summary);
    for (const fact of section.facts || []) lines.push(textFact(fact));
    for (const item of section.items || []) {
      if (item.provider) {
        lines.push(`${item.provider}: ${item.verdict ?? item.kind ?? 'OBSERVED'}${item.kind ? ` // ${item.kind}` : ''}`);
        if (item.semanticNote) lines.push(`  ${item.semanticNote}`);
        for (const fact of item.facts || []) lines.push(textFact(fact, '  '));
        for (const fact of item.detailFacts || []) lines.push(textFact(fact, '  '));
      } else {
        if (item.title) lines.push(item.title);
        for (const fact of item.facts || []) lines.push(textFact(fact, '  '));
        for (const fact of item.detailFacts || []) lines.push(textFact(fact, '  '));
      }
    }
    for (const failure of section.failures || []) {
      lines.push(`${failure.provider}: ${failure.label}`);
      if (failure.summary) lines.push(`  ${failure.summary}`);
      for (const fact of failure.details || []) lines.push(textFact(fact, '  '));
    }
    out.push(...textSection(section.title, lines));
  }

  return `${out.join('\n').trimEnd()}\n`;
}

export function jsonLines(envelope) {
  return JSON.stringify(envelope, null, 2)
    .split('\n')
    .map((text, index) => ({ number: index + 1, text }));
}
