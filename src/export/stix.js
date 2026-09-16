const MAX_OBJECTS = 100;
const MAX_REFERENCES = 20;
const UUID_NAMESPACE_URL = '6ba7b811-9dad-11d1-80b4-00c04fd430c8';
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
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

function isExportableEvidence(item) {
  return item?.policy?.distribution !== 'internal_only';
}

function internalOnlyProviders(evidence) {
  return new Set((Array.isArray(evidence) ? evidence : [])
    .filter(item => !isExportableEvidence(item))
    .map(item => item?.provider)
    .filter(value => typeof value === 'string' && value));
}

function externalReferences(evidence) {
  const seen = new Set();
  const output = [];
  for (const item of Array.isArray(evidence) ? evidence : []) {
    if (!isExportableEvidence(item)) continue;
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

const rotateLeft = (value, shift) => ((value << shift) | (value >>> (32 - shift))) >>> 0;

function uuidBytes(value) {
  if (typeof value !== 'string' || !UUID_RE.test(value)) throw new TypeError('valid UUID namespace required');
  const hex = value.replaceAll('-', '').toLowerCase();
  return Uint8Array.from({ length: 16 }, (_, index) => Number.parseInt(hex.slice(index * 2, (index * 2) + 2), 16));
}

function sha1Digest(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const bitLength = bytes.byteLength * 8;
  const paddedLength = Math.ceil((bytes.byteLength + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLength);
  padded.set(bytes);
  padded[bytes.byteLength] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(paddedLength - 8, Math.floor(bitLength / 0x1_0000_0000), false);
  view.setUint32(paddedLength - 4, bitLength >>> 0, false);

  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;
  let h4 = 0xc3d2e1f0;
  const words = new Uint32Array(80);

  for (let offset = 0; offset < paddedLength; offset += 64) {
    for (let index = 0; index < 16; index += 1) words[index] = view.getUint32(offset + (index * 4), false);
    for (let index = 16; index < 80; index += 1) {
      words[index] = rotateLeft(words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16], 1);
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    for (let index = 0; index < 80; index += 1) {
      let f;
      let k;
      if (index < 20) {
        f = (b & c) | (~b & d);
        k = 0x5a827999;
      } else if (index < 40) {
        f = b ^ c ^ d;
        k = 0x6ed9eba1;
      } else if (index < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8f1bbcdc;
      } else {
        f = b ^ c ^ d;
        k = 0xca62c1d6;
      }
      const next = (rotateLeft(a, 5) + f + e + k + words[index]) >>> 0;
      e = d;
      d = c;
      c = rotateLeft(b, 30);
      b = a;
      a = next;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
  }

  const digest = new Uint8Array(20);
  const digestView = new DataView(digest.buffer);
  [h0, h1, h2, h3, h4].forEach((word, index) => digestView.setUint32(index * 4, word, false));
  return digest;
}

export function uuidV5(name, namespace = UUID_NAMESPACE_URL) {
  const namespaceBytes = uuidBytes(namespace);
  const nameBytes = new TextEncoder().encode(String(name));
  const input = new Uint8Array(namespaceBytes.byteLength + nameBytes.byteLength);
  input.set(namespaceBytes);
  input.set(nameBytes, namespaceBytes.byteLength);
  const bytes = sha1Digest(input).slice(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map(value => value.toString(16).padStart(2, '0')).join('');
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
    .find(item => isExportableEvidence(item) && item?.observation?.kind === 'attack_knowledge' && item?.observation?.attributes?.stixId);
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
  const blockedProviders = internalOnlyProviders(enrichment.evidence);
  const seen = new Set();
  const output = [];
  for (const rel of Array.isArray(enrichment.relationships) ? enrichment.relationships : []) {
    if (typeof rel?.provider === 'string' && blockedProviders.has(rel.provider)) continue;
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

export function randomUUID() {
  return crypto.randomUUID();
}
