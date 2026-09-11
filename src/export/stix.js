import { createHash, randomUUID } from 'node:crypto';

const MAX_OBJECTS = 100;
const MAX_REFERENCES = 20;
const UUID_NAMESPACE_URL = Buffer.from('6ba7b8119dad11d180b400c04fd430c8', 'hex');
const SUPPORTED_ATTACK_TYPES = new Set([
  'attack-pattern', 'intrusion-set', 'malware', 'tool', 'campaign', 'course-of-action',
  'x-mitre-tactic', 'x-mitre-data-source', 'x-mitre-data-component', 'x-mitre-detection-strategy',
]);

function stixString(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

function validHttpUrl(value) {
  try {
    const url = new URL(String(value));
    return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password ? url.toString() : null;
  } catch {
    return null;
  }
}

function externalReferences(evidence) {
  const seen = new Set();
  const output = [];
  for (const item of Array.isArray(evidence) ? evidence : []) {
    for (const value of Array.isArray(item?.references) ? item.references : []) {
      const url = validHttpUrl(value);
      if (!url) continue;
      const key = `${item?.provider ?? 'gateway'}\u0000${url}`;
      if (seen.has(key)) continue;
      seen.add(key);
      output.push({ source_name: String(item?.provider ?? 'gateway').slice(0, 100), url });
      if (output.length >= MAX_REFERENCES) return output;
    }
  }
  return output;
}

function patternFor(indicator, type) {
  if (type === 'ip') {
    const object = String(indicator).includes(':') ? 'ipv6-addr' : 'ipv4-addr';
    return `[${object}:value = '${stixString(indicator)}']`;
  }
  if (type === 'domain') return `[domain-name:value = '${stixString(indicator)}']`;
  if (type === 'url') return `[url:value = '${stixString(indicator)}']`;
  if (type === 'hash') {
    const algorithm = indicator.length === 32 ? 'MD5' : indicator.length === 40 ? 'SHA-1' : indicator.length === 64 ? 'SHA-256' : null;
    return algorithm ? `[file:hashes.'${algorithm}' = '${stixString(indicator)}']` : null;
  }
  if (type === 'asn') {
    const number = Number(String(indicator).replace(/^AS/i, ''));
    return Number.isSafeInteger(number) && number > 0 ? `[autonomous-system:number = ${number}]` : null;
  }
  return null;
}

function timestamp(value, fallback) {
  const ms = Date.parse(value ?? '');
  return Number.isFinite(ms) ? new Date(ms).toISOString() : fallback;
}

function canonicalIdentity(type, value) {
  const text = String(value ?? '').trim();
  if (type === 'hash' || type === 'domain') return text.toLowerCase();
  if (type === 'cve' || type === 'asn') return text.toUpperCase();
  return text;
}

function uuidV5(name) {
  const hash = createHash('sha1')
    .update(UUID_NAMESPACE_URL)
    .update(Buffer.from(String(name), 'utf8'))
    .digest();
  const bytes = Buffer.from(hash.subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function newId(type, uuid, identity) {
  const value = uuid ? uuid() : uuidV5(`para11ax-stix\u0000${type}\u0000${identity}`);
  return `${type}--${value}`;
}

function primaryObject(enrichment, now, uuid) {
  const refs = externalReferences(enrichment.evidence);
  const identity = `${enrichment.type}\u0000${canonicalIdentity(enrichment.type, enrichment.indicator)}`;
  if (enrichment.type === 'cve') {
    return {
      type: 'vulnerability',
      spec_version: '2.1',
      id: newId('vulnerability', uuid, identity),
      created: now,
      modified: now,
      name: enrichment.indicator,
      external_references: [{ source_name: 'cve', external_id: enrichment.indicator }],
    };
  }

  const pattern = patternFor(enrichment.indicator, enrichment.type);
  if (!pattern) return null;
  const object = {
    type: 'indicator',
    spec_version: '2.1',
    id: newId('indicator', uuid, identity),
    created: now,
    modified: now,
    valid_from: timestamp(enrichment.queriedAt, now),
    pattern_type: 'stix',
    pattern,
    name: `${enrichment.type}:${String(enrichment.indicator).slice(0, 256)}`,
  };
  if (refs.length) object.external_references = refs;
  return object;
}

function attackObject(enrichment) {
  const evidence = (Array.isArray(enrichment.evidence) ? enrichment.evidence : [])
    .find(item => item?.observation?.kind === 'attack_knowledge' && item?.observation?.attributes?.stixId);
  if (!evidence) return null;
  const a = evidence.observation.attributes ?? {};
  const type = String(a.stixType ?? '');
  const id = String(a.stixId ?? '');
  if (!SUPPORTED_ATTACK_TYPES.has(type) || !id.startsWith(`${type}--`)) return null;

  const created = timestamp(evidence.observation.firstSeen, null);
  const modified = timestamp(evidence.observation.lastSeen, created);
  if (!created || !modified) return null;
  const object = {
    type,
    spec_version: '2.1',
    id,
    created,
    modified,
    name: String(a.name ?? enrichment.indicator).slice(0, 512),
  };
  if (typeof a.description === 'string' && a.description) object.description = a.description.slice(0, 4000);
  if (type === 'malware') object.is_family = false;
  if (type === 'attack-pattern' && Array.isArray(a.tactics) && a.tactics.length) {
    object.kill_chain_phases = [...new Set(a.tactics.map(String))].slice(0, 20).map(phase_name => ({ kill_chain_name: 'mitre-attack', phase_name }));
  }
  const sourceUrl = (Array.isArray(evidence.references) ? evidence.references : []).map(validHttpUrl).find(Boolean);
  object.external_references = [{
    source_name: 'mitre-attack',
    external_id: enrichment.indicator,
    ...(sourceUrl ? { url: sourceUrl } : {}),
  }];
  return object;
}

function relationshipObjects(enrichment, now, uuid) {
  const seen = new Set();
  const output = [];
  for (const rel of Array.isArray(enrichment.relationships) ? enrichment.relationships : []) {
    const targetType = rel?.targetType;
    const target = typeof rel?.target === 'string' ? rel.target.trim() : '';
    let type = null;
    if (targetType === 'actor' && rel?.type === 'attributed_to') type = 'threat-actor';
    if (targetType === 'malware' && rel?.type === 'uses') type = 'malware';
    if (!type || !target) continue;
    const key = `${type}\u0000${target.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const object = {
      type,
      spec_version: '2.1',
      id: newId(type, uuid, key),
      created: now,
      modified: now,
      name: target.slice(0, 512),
    };
    if (type === 'malware') object.is_family = false;
    output.push(object);
  }
  return output;
}

function assertGatewayEnrichment(value) {
  if (!value || typeof value !== 'object' || typeof value.schemaVersion !== 'string' || typeof value.gatewayVersion !== 'string' || typeof value.requestId !== 'string' || typeof value.indicator !== 'string' || typeof value.type !== 'string' || !Array.isArray(value.evidence) || !Array.isArray(value.relationships)) {
    throw new TypeError('gateway enrichment required');
  }
}

export function toStixBundle(enrichment, {
  maxObjects = MAX_OBJECTS,
  now = () => new Date().toISOString(),
  uuid = null,
} = {}) {
  assertGatewayEnrichment(enrichment);
  if (!Number.isInteger(maxObjects) || maxObjects < 1 || maxObjects > MAX_OBJECTS) throw new TypeError('maxObjects must be between 1 and 100');
  if (uuid !== null && typeof uuid !== 'function') throw new TypeError('uuid must be a function');

  const created = timestamp(now(), new Date().toISOString());
  const objects = [];
  const first = enrichment.type === 'attack' ? attackObject(enrichment) : primaryObject(enrichment, created, uuid);
  if (first) objects.push(first);
  if (objects.length < maxObjects) objects.push(...relationshipObjects(enrichment, created, uuid).slice(0, maxObjects - objects.length));
  const boundedObjects = objects.slice(0, maxObjects);
  const bundleIdentity = boundedObjects.map(object => object.id).sort().join('|') || `${enrichment.type}\u0000${canonicalIdentity(enrichment.type, enrichment.indicator)}`;

  return {
    type: 'bundle',
    id: newId('bundle', uuid, bundleIdentity),
    objects: boundedObjects,
  };
}

export { randomUUID };
