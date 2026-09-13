import { createHash, isIP } from 'node:crypto';

const SCHEMA_VERSION = 'domain-investigation-v1.0';
const HANDOFF_SCHEMA_VERSION = 'domain-investigation-handoff-v1.0';
const MAX_RECORDS = 500;
const MAX_IMPORT_BYTES = 2 * 1024 * 1024;
const MAX_FIELD_LENGTH = 4096;
const MAX_HANDOFF_BYTES = 128_000;

const DIRECT_SEMANTIC_CLASSES = new Set(['reputation', 'malware_association', 'exploitation']);
const DIRECT_VERDICTS = new Set(['malicious', 'phishing', 'listed', 'known_exploited']);
const POSITIVE_CONTEXT_VERDICTS = new Set(['malicious', 'phishing', 'listed', 'known_exploited', 'suspicious', 'associated', 'observed']);
const NEGATIVE_VERDICTS = new Set(['benign', 'clean']);
const IOC_TYPES = new Set(['domain', 'url', 'ip', 'hash', 'asn', 'certificate', 'cve']);

const SURFACE_FIELDS = Object.freeze([
  'host', 'ip', 'url', 'port', 'protocol', 'service', 'technology', 'status', 'source', 'reference',
]);
const VULN_FIELDS = Object.freeze([
  'host', 'url', 'templateId', 'cve', 'severity', 'title', 'matchedAt', 'source', 'reference',
]);

function utf8Bytes(value) {
  return Buffer.byteLength(JSON.stringify(value), 'utf8');
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]));
  }
  return value;
}

function stableHash(prefix, value) {
  return `${prefix}-${createHash('sha256').update(JSON.stringify(stable(value))).digest('hex').slice(0, 20).toUpperCase()}`;
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function uniqueSorted(values) {
  return [...new Set(values.filter(value => value !== undefined && value !== null && String(value).length > 0).map(String))].sort();
}

function normalizeDomain(value) {
  if (typeof value !== 'string') throw new TypeError('domain must be a string');
  const domain = value.trim().toLowerCase().replace(/\.$/, '');
  if (!domain || domain.length > 253 || !domain.includes('.') || domain.includes('://')) throw new TypeError('invalid domain target');
  const labels = domain.split('.');
  if (labels.some(label => !label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label))) {
    throw new TypeError('invalid domain target');
  }
  return domain;
}

function normalizeReference(value) {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'string') throw new TypeError('reference must be an HTTP(S) string');
  if (value.length > MAX_FIELD_LENGTH) throw new RangeError(`reference exceeds ${MAX_FIELD_LENGTH} characters`);
  let parsed;
  try { parsed = new URL(value); } catch { throw new TypeError('reference must be a valid HTTP(S) URL'); }
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new TypeError('reference must use HTTP(S)');
  if (parsed.username || parsed.password) throw new TypeError('reference must not contain credentials');
  return parsed.toString();
}

function normalizeScalar(value, field) {
  if (value === undefined || value === null || value === '') return null;
  if (!['string', 'number', 'boolean'].includes(typeof value)) throw new TypeError(`${field} must be a scalar field`);
  const text = String(value).trim();
  if (text.length > MAX_FIELD_LENGTH) throw new RangeError(`${field} exceeds ${MAX_FIELD_LENGTH} characters`);
  return text || null;
}

function normalizeRecord(record, fields, prefix) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) throw new TypeError(`${prefix} record must be an object`);
  for (const [key, value] of Object.entries(record)) {
    if (!fields.includes(key)) continue;
    if (value !== undefined && value !== null && value !== '' && !['string', 'number', 'boolean'].includes(typeof value)) {
      throw new TypeError(`${key} must be a scalar field`);
    }
  }
  const normalized = {};
  for (const field of fields) {
    const value = field === 'reference' ? normalizeReference(record[field]) : normalizeScalar(record[field], field);
    if (value !== null) normalized[field] = value;
  }
  const identity = { ...normalized };
  delete identity.id;
  return { id: stableHash(prefix, identity), ...normalized };
}

function normalizeImport(input, fields, prefix) {
  if (!Array.isArray(input)) throw new TypeError(`${prefix} import must be an array`);
  if (input.length > MAX_RECORDS) throw new RangeError(`${prefix} import exceeds ${MAX_RECORDS} record limit`);
  if (utf8Bytes(input) > MAX_IMPORT_BYTES) throw new RangeError(`${prefix} import exceeds 2 MiB limit`);
  return input.map(record => normalizeRecord(record, fields, prefix));
}

function validateEnrichment(enrichment, expectedTarget) {
  if (!enrichment || typeof enrichment !== 'object' || Array.isArray(enrichment)) throw new TypeError('Evidence v2 enrichment is required');
  if (enrichment.schemaVersion !== 'evidence-v2.0') throw new TypeError('Evidence v2 enrichment is required');
  if (enrichment.type !== 'domain') throw new TypeError('Domain Investigation requires domain Evidence v2');
  const indicator = normalizeDomain(enrichment.indicator);
  if (expectedTarget !== undefined && normalizeDomain(expectedTarget) !== indicator) throw new TypeError('target domain does not match enrichment indicator');
  if (!Array.isArray(enrichment.evidence)) throw new TypeError('Evidence v2 enrichment must contain evidence[]');
  return indicator;
}

function normalizeIocValue(type, raw) {
  if (raw === undefined || raw === null) return null;
  const value = String(raw).trim();
  if (!value || value.length > MAX_FIELD_LENGTH) return null;
  if (type === 'domain') {
    try { return normalizeDomain(value); } catch { return null; }
  }
  if (type === 'url') {
    try {
      const url = new URL(value);
      if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
      return url.toString();
    } catch { return null; }
  }
  if (type === 'ip') return isIP(value) ? value : null;
  if (type === 'hash') return /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(value) ? value.toLowerCase() : null;
  if (type === 'asn') {
    const match = value.toUpperCase().match(/^(?:AS)?(\d{1,10})$/);
    return match ? `AS${match[1]}` : null;
  }
  if (type === 'certificate') return value.toLowerCase();
  if (type === 'cve') return /^CVE-\d{4}-\d{4,}$/i.test(value) ? value.toUpperCase() : null;
  return null;
}

function relationshipIocType(targetType) {
  const value = String(targetType ?? '').toLowerCase();
  if (IOC_TYPES.has(value)) return value;
  if (['sha256', 'sha1', 'md5', 'file_hash'].includes(value)) return 'hash';
  if (['cert', 'cert-sha256', 'certificate_sha256'].includes(value)) return 'certificate';
  return null;
}

function addIoc(map, type, rawValue, provenance) {
  const value = normalizeIocValue(type, rawValue);
  if (!value) return;
  const key = `${type}:${value}`;
  if (!map.has(key)) {
    map.set(key, {
      type,
      value,
      authorities: new Set(),
      providers: new Set(),
      evidenceFingerprints: new Set(),
      operatorRecordIds: new Set(),
      relationships: new Set(),
      directSources: new Set(),
      contextSources: new Set(),
      contradictions: [],
    });
  }
  const item = map.get(key);
  if (provenance.authority) item.authorities.add(provenance.authority);
  if (provenance.provider) item.providers.add(provenance.provider);
  if (provenance.fingerprint) item.evidenceFingerprints.add(provenance.fingerprint);
  if (provenance.recordId) item.operatorRecordIds.add(provenance.recordId);
  if (provenance.relationship) item.relationships.add(provenance.relationship);
  if (provenance.direct) item.directSources.add(provenance.provider);
  if (provenance.context && provenance.provider) item.contextSources.add(provenance.provider);
  if (provenance.contradiction) item.contradictions.push(provenance.contradiction);
}

function evidenceFacts(item, exactTarget) {
  const verdict = String(item?.observation?.verdict ?? '').toLowerCase();
  const semanticClass = String(item?.semantics?.semanticClass ?? '').toLowerCase();
  const provider = typeof item?.provider === 'string' ? item.provider : null;
  const direct = exactTarget && provider && DIRECT_VERDICTS.has(verdict) && DIRECT_SEMANTIC_CLASSES.has(semanticClass);
  const contradiction = exactTarget && provider && NEGATIVE_VERDICTS.has(verdict)
    ? { provider, verdict, semanticClass: semanticClass || 'unknown' }
    : null;
  const context = provider && !direct && POSITIVE_CONTEXT_VERDICTS.has(verdict);
  return { provider, verdict, semanticClass, direct, context, contradiction };
}

function buildIocs(target, enrichment, surface, vulnerabilities) {
  const map = new Map();
  const evidence = enrichment.evidence;

  for (const item of evidence) {
    const fingerprint = item?.integrity?.fingerprint ?? null;
    const facts = evidenceFacts(item, true);
    addIoc(map, 'domain', target, {
      authority: 'evidence_v2',
      provider: facts.provider,
      fingerprint,
      direct: facts.direct,
      context: facts.context,
      contradiction: facts.contradiction,
    });
    for (const relationship of Array.isArray(item?.relationships) ? item.relationships : []) {
      const type = relationshipIocType(relationship?.targetType);
      if (!type) continue;
      addIoc(map, type, relationship?.target, {
        authority: 'evidence_v2',
        provider: facts.provider,
        fingerprint,
        relationship: relationship?.relationship ?? 'related',
        context: true,
      });
    }
  }

  if (!map.has(`domain:${target}`)) addIoc(map, 'domain', target, { authority: 'evidence_v2' });

  for (const record of surface) {
    addIoc(map, 'domain', record.host, { authority: 'operator_context', recordId: record.id, relationship: 'surface_host' });
    addIoc(map, 'ip', record.ip, { authority: 'operator_context', recordId: record.id, relationship: 'surface_ip' });
    addIoc(map, 'url', record.url, { authority: 'operator_context', recordId: record.id, relationship: 'surface_url' });
  }
  for (const record of vulnerabilities) {
    addIoc(map, 'domain', record.host, { authority: 'operator_context', recordId: record.id, relationship: 'vulnerability_host' });
    addIoc(map, 'url', record.url ?? record.matchedAt, { authority: 'operator_context', recordId: record.id, relationship: 'vulnerability_url' });
    addIoc(map, 'cve', record.cve, { authority: 'operator_context', recordId: record.id, relationship: 'vulnerability_cve' });
  }

  return [...map.values()].map(item => ({
    type: item.type,
    value: item.value,
    authorities: uniqueSorted([...item.authorities]),
    providers: uniqueSorted([...item.providers]),
    evidenceFingerprints: uniqueSorted([...item.evidenceFingerprints]),
    operatorRecordIds: uniqueSorted([...item.operatorRecordIds]),
    relationships: uniqueSorted([...item.relationships]),
    _directSources: uniqueSorted([...item.directSources]),
    _contextSources: uniqueSorted([...item.contextSources]),
    _contradictions: item.contradictions.sort((a, b) => a.provider.localeCompare(b.provider)),
  })).sort((a, b) => `${a.type}:${a.value}`.localeCompare(`${b.type}:${b.value}`));
}

function dispositionFor(ioc) {
  const directSources = ioc._directSources;
  const contextSources = ioc._contextSources.filter(source => !directSources.includes(source));
  const contradictions = ioc._contradictions;
  const hasOperatorContext = ioc.authorities.includes('operator_context');

  if (directSources.length >= 2 && contradictions.length === 0) {
    return {
      disposition: 'BLOCK',
      ruleId: 'DI-BLOCK-2-DIRECT',
      reasons: ['At least two independent direct malicious Evidence v2 providers agree on the exact IOC.'],
    };
  }
  if (directSources.length >= 1 && (contextSources.length >= 1 || hasOperatorContext || directSources.length >= 2)) {
    return {
      disposition: 'BLOCK_CANDIDATE',
      ruleId: contradictions.length ? 'DI-CANDIDATE-CONTRADICTION' : 'DI-CANDIDATE-DIRECT-CONTEXT',
      reasons: contradictions.length
        ? ['Direct malicious evidence exists, but explicit negative evidence creates contradiction pressure requiring analyst review.']
        : ['Direct malicious evidence is independently corroborated by contextual or operator evidence; human approval remains required.'],
    };
  }
  if (directSources.length === 1) {
    return {
      disposition: 'MONITOR',
      ruleId: 'DI-MONITOR-ONE-DIRECT',
      reasons: ['Only one direct malicious Evidence v2 source is present without independent corroboration.'],
    };
  }
  if (contextSources.length || hasOperatorContext || ioc.providers.length) {
    return {
      disposition: 'MONITOR',
      ruleId: 'DI-MONITOR-CONTEXT',
      reasons: ['Only contextual, infrastructure, Webamon, exposure, or operator evidence is present; it is not a direct malicious vote.'],
    };
  }
  return {
    disposition: 'DO_NOT_BLOCK',
    ruleId: 'DI-NO-DIRECT-EVIDENCE',
    reasons: ['No direct malicious Evidence v2 source supports blocking this IOC.'],
  };
}

function buildRecommendations(iocs) {
  return iocs.map(ioc => {
    const decision = dispositionFor(ioc);
    return {
      type: ioc.type,
      value: ioc.value,
      disposition: decision.disposition,
      ruleId: decision.ruleId,
      authority: ioc.authorities,
      directSources: ioc._directSources,
      contextSources: ioc._contextSources.filter(source => !ioc._directSources.includes(source)),
      contradictions: ioc._contradictions,
      reasons: decision.reasons,
    };
  });
}

function publicIocs(iocs) {
  return iocs.map(({ _directSources, _contextSources, _contradictions, ...item }) => item);
}

function buildPassive(enrichment) {
  const evidence = enrichment.evidence;
  const providers = uniqueSorted(evidence.map(item => item?.provider).filter(Boolean));
  const evidenceFingerprints = uniqueSorted(evidence.map(item => item?.integrity?.fingerprint).filter(value => /^[a-f0-9]{64}$/i.test(value ?? '')));
  const references = uniqueSorted(evidence.flatMap(item => Array.isArray(item?.references) ? item.references : []).map(value => {
    try { return normalizeReference(value); } catch { return null; }
  }).filter(Boolean));
  const webamonEvidence = evidence.filter(item => item?.provider === 'webamon');
  return {
    requestId: enrichment.requestId ?? null,
    queriedAt: enrichment.queriedAt ?? null,
    profile: enrichment.profile ?? null,
    status: enrichment.status ?? null,
    providers,
    evidenceFingerprints,
    references,
    evidenceCount: evidence.length,
    webamon: {
      present: webamonEvidence.length > 0,
      evidenceCount: webamonEvidence.length,
      fingerprints: uniqueSorted(webamonEvidence.map(item => item?.integrity?.fingerprint).filter(Boolean)),
    },
  };
}

function buildPhases(passive, surface, vulnerabilities) {
  return [
    { id: 'passive', state: passive.evidenceCount ? 'COMPLETE' : 'COMPLETE_EMPTY', gap: passive.evidenceCount ? null : 'no_passive_evidence_records' },
    { id: 'webamon', state: passive.webamon.present ? 'COMPLETE' : 'NOT_OBSERVED', gap: passive.webamon.present ? null : 'webamon_not_represented_in_supplied_enrichment' },
    { id: 'surface', state: surface.length ? 'IMPORTED' : 'NOT_IMPORTED', gap: surface.length ? null : 'authorized_surface_results_not_imported' },
    { id: 'vulnerability', state: vulnerabilities.length ? 'IMPORTED' : 'NOT_IMPORTED', gap: vulnerabilities.length ? null : 'authorized_vulnerability_results_not_imported' },
    { id: 'correlation', state: 'COMPLETE', gap: null },
    { id: 'output', state: 'COMPLETE', gap: null },
  ];
}

function buildLimitations(passive, surface, vulnerabilities) {
  const limitations = [
    'PARA11AX did not execute active scanning; imported discovery and vulnerability findings are operator context only.',
    'Block recommendations are advisory and require human approval before enforcement.',
  ];
  if (!passive.webamon.present) limitations.push('Webamon evidence is not represented in the supplied Evidence v2 enrichment.');
  if (!surface.length) limitations.push('No authorized surface-discovery result set was imported.');
  if (!vulnerabilities.length) limitations.push('No authorized vulnerability result set was imported.');
  return limitations;
}

function buildReport(target, passive, surface, vulnerabilities, iocs, recommendations, limitations) {
  const counts = recommendations.reduce((acc, item) => {
    acc[item.disposition] = (acc[item.disposition] ?? 0) + 1;
    return acc;
  }, {});
  const text = [
    `Domain Investigation v1 — ${target}`,
    `Passive Evidence v2: ${passive.evidenceCount} records from ${passive.providers.length} providers. Webamon represented: ${passive.webamon.present ? 'yes' : 'no'}.`,
    `Operator context: ${surface.length} surface records and ${vulnerabilities.length} vulnerability records.`,
    'Authority boundary: imported discovery and vulnerability findings are operator context, not Evidence v2.',
    'PARA11AX did not execute active scanning; active discovery/scanning must be separately authorized and performed outside this server workflow.',
    `IOC projection: ${iocs.length} unique observables. Recommendations: BLOCK=${counts.BLOCK ?? 0}, BLOCK_CANDIDATE=${counts.BLOCK_CANDIDATE ?? 0}, MONITOR=${counts.MONITOR ?? 0}, DO_NOT_BLOCK=${counts.DO_NOT_BLOCK ?? 0}.`,
    `Limitations: ${limitations.join(' ')}`,
  ].join('\n');
  return { target, passiveEvidenceCount: passive.evidenceCount, surfaceCount: surface.length, vulnerabilityCount: vulnerabilities.length, iocCount: iocs.length, recommendationCounts: counts, text };
}

function buildHandoff(target, passive, surface, vulnerabilities, phases, iocs, recommendations, limitations) {
  const unresolvedPivots = recommendations
    .filter(item => item.disposition === 'MONITOR' || item.disposition === 'BLOCK_CANDIDATE')
    .slice(0, 32)
    .map(item => ({ type: item.type, value: item.value, disposition: item.disposition }));
  const actionItems = recommendations
    .filter(item => item.disposition === 'BLOCK' || item.disposition === 'BLOCK_CANDIDATE')
    .slice(0, 32)
    .map(item => ({ type: item.type, value: item.value, disposition: item.disposition, ruleId: item.ruleId }));
  const nextActions = [];
  if (!surface.length) nextActions.push('If authorized, perform external surface discovery and import the bounded normalized results.');
  if (!vulnerabilities.length) nextActions.push('If authorized, perform external vulnerability assessment and import the bounded normalized results.');
  if (!passive.webamon.present) nextActions.push('Re-run canonical domain enrichment with Webamon configured if Webamon coverage is required.');
  if (actionItems.length) nextActions.push('Human-review block recommendations before any enforcement action.');
  nextActions.push('Pivot unresolved observables through existing bounded PARA11AX enrichment/operator workflows as appropriate.');

  const base = {
    schemaVersion: HANDOFF_SCHEMA_VERSION,
    target: { type: 'domain', value: target },
    phases: phases.map(({ id, state, gap }) => ({ id, state, gap })),
    evidence: { providers: passive.providers, fingerprints: passive.evidenceFingerprints },
    operatorContext: { recordIds: uniqueSorted([...surface, ...vulnerabilities].map(record => record.id)) },
    unresolvedPivots,
    actionItems,
    limitations,
    nextActions,
  };
  const serializedBytes = utf8Bytes(base);
  if (serializedBytes >= MAX_HANDOFF_BYTES) throw new RangeError('handoff context exceeds bounded context budget');
  return { ...base, contextBudget: { serializedBytes, maximumBytes: MAX_HANDOFF_BYTES, rawEvidenceIncluded: false } };
}

function rebuild(enrichment, surface, vulnerabilities, expectedTarget) {
  const target = validateEnrichment(enrichment, expectedTarget);
  const passive = buildPassive(enrichment);
  const internalIocs = buildIocs(target, enrichment, surface, vulnerabilities);
  const recommendations = buildRecommendations(internalIocs);
  const iocs = publicIocs(internalIocs);
  const phases = buildPhases(passive, surface, vulnerabilities);
  const limitations = buildLimitations(passive, surface, vulnerabilities);
  const report = buildReport(target, passive, surface, vulnerabilities, iocs, recommendations, limitations);
  const handoff = buildHandoff(target, passive, surface, vulnerabilities, phases, iocs, recommendations, limitations);
  return deepFreeze({
    schemaVersion: SCHEMA_VERSION,
    target: { type: 'domain', value: target },
    passive,
    imports: { surface, vulnerabilities },
    iocs,
    recommendations,
    phases,
    limitations,
    report,
    handoff,
    _authoritative: { enrichment },
  });
}

function validateArtifact(artifact) {
  if (!artifact || artifact.schemaVersion !== SCHEMA_VERSION || artifact.target?.type !== 'domain' || !artifact._authoritative?.enrichment) {
    throw new TypeError('valid Domain Investigation v1 artifact is required');
  }
  validateEnrichment(artifact._authoritative.enrichment, artifact.target.value);
  return artifact;
}

export function createDomainInvestigation(enrichment, expectedTarget) {
  return rebuild(enrichment, [], [], expectedTarget);
}

export function importDomainSurface(artifact, input) {
  validateArtifact(artifact);
  const surface = normalizeImport(input, SURFACE_FIELDS, 'SURF');
  return rebuild(artifact._authoritative.enrichment, surface, artifact.imports.vulnerabilities, artifact.target.value);
}

export function importDomainVulnerabilities(artifact, input) {
  validateArtifact(artifact);
  const vulnerabilities = normalizeImport(input, VULN_FIELDS, 'VULN');
  return rebuild(artifact._authoritative.enrichment, artifact.imports.surface, vulnerabilities, artifact.target.value);
}

export const DOMAIN_INVESTIGATION_SCHEMA_VERSION = SCHEMA_VERSION;
