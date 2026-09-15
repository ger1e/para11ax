import { createHash } from 'node:crypto';
import { isIP } from 'node:net';

const SCHEMA_VERSION = 'evidence-promotion-v1.0';
const MAX_SOURCES = 256;
const MAX_EVENTS = 512;
const MAX_TEXT = 4096;
const MAX_ID = 160;
const MAX_REFERENCES = 16;
const MAX_REFERENCE = 2048;
const OBSERVABLE_TYPES = new Set(['domain', 'url', 'ip', 'hash', 'asn', 'certificate', 'cve']);
const SOURCE_KEYS = new Set(['id', 'kind', 'capturedAt', 'source', 'summary', 'references', 'observable', 'observation']);
const OBSERVABLE_KEYS = new Set(['type', 'value']);
const OBSERVATION_KEYS = new Set(['kind', 'verdict']);
const EVENT_TYPES = new Set(['approved', 'rejected', 'revoked', 'superseded', 'expired']);
const SECRET_PATTERN = /(?:api[_-]?key|password|passwd|pwd|secret|token)\s*[:=]\s*(?!<redacted>|redacted\b)\S+/i;

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]));
  }
  return value;
}

function hash(value) {
  return createHash('sha256').update(JSON.stringify(stable(value))).digest('hex');
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function exactKeys(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (!keys.has(key)) throw new TypeError(`${label} contains unsupported field: ${key}`);
  }
  for (const key of keys) {
    if (!(key in value)) throw new TypeError(`${label} is missing required field: ${key}`);
  }
}

function text(value, label, max = MAX_TEXT) {
  if (typeof value !== 'string') throw new TypeError(`${label} must be a string`);
  const normalized = value.trim();
  if (!normalized || normalized.length > max) throw new RangeError(`${label} exceeds ${max} character limit or is empty`);
  if (SECRET_PATTERN.test(normalized)) throw new TypeError(`${label} contains secret or credential material`);
  return normalized;
}

function timestamp(value, label) {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) throw new TypeError(`${label} must be an ISO timestamp`);
  const normalized = new Date(value).toISOString();
  if (normalized !== value) throw new TypeError(`${label} must use canonical ISO timestamp form`);
  return normalized;
}

function reference(value) {
  if (typeof value !== 'string' || !value || value.length > MAX_REFERENCE) throw new TypeError('reference must be a bounded string');
  let parsed;
  try { parsed = new URL(value); } catch { throw new TypeError('reference must be a valid HTTP(S) URL'); }
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new TypeError('reference must use HTTP(S)');
  if (parsed.username || parsed.password) throw new TypeError('reference must not contain credentials');
  if (SECRET_PATTERN.test(parsed.search) || SECRET_PATTERN.test(parsed.hash)) throw new TypeError('reference must not contain secret or credential material');
  return parsed.toString();
}

function normalizeObservable(observable) {
  exactKeys(observable, OBSERVABLE_KEYS, 'observable');
  const type = text(observable.type, 'observable type', 32).toLowerCase();
  if (!OBSERVABLE_TYPES.has(type)) throw new TypeError('unsupported observable type');
  let value = text(observable.value, 'observable value');
  if (type === 'domain') {
    value = value.toLowerCase().replace(/\.$/, '');
    if (!value.includes('.') || value.includes('://')) throw new TypeError('invalid domain observable');
  } else if (type === 'url') {
    const parsed = new URL(value);
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) throw new TypeError('invalid URL observable');
    value = parsed.toString();
  } else if (type === 'ip') {
    if (!isIP(value)) throw new TypeError('invalid IP observable');
  } else if (type === 'hash') {
    if (!/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(value)) throw new TypeError('invalid hash observable');
    value = value.toLowerCase();
  } else if (type === 'asn') {
    const match = value.toUpperCase().match(/^(?:AS)?(\d{1,10})$/);
    if (!match) throw new TypeError('invalid ASN observable');
    value = `AS${match[1]}`;
  } else if (type === 'cve') {
    if (!/^CVE-\d{4}-\d{4,}$/i.test(value)) throw new TypeError('invalid CVE observable');
    value = value.toUpperCase();
  } else if (type === 'certificate') {
    value = value.toLowerCase();
  }
  return { type, value };
}

function normalizeObservation(observation) {
  exactKeys(observation, OBSERVATION_KEYS, 'observation');
  return {
    kind: text(observation.kind, 'observation kind', 96),
    verdict: text(observation.verdict, 'observation verdict', 64).toLowerCase(),
  };
}

function normalizeSource(source, index) {
  exactKeys(source, SOURCE_KEYS, `operator artifact[${index}]`);
  const kind = text(source.kind, 'operator artifact kind', 64);
  if (/analyst[_-]?attestation|analyst[_-]?promoted|promoted[_-]?evidence/i.test(kind)) {
    throw new TypeError('recursive promotion from analyst attestation is not permitted');
  }
  if (!Array.isArray(source.references) || source.references.length === 0 || source.references.length > MAX_REFERENCES) {
    throw new TypeError(`operator artifact references must contain 1-${MAX_REFERENCES} URLs`);
  }
  const normalized = {
    sourceArtifactId: text(source.id, 'operator artifact id', MAX_ID),
    sourceKind: kind,
    capturedAt: timestamp(source.capturedAt, 'operator artifact capturedAt'),
    source: text(source.source, 'operator artifact source', 160),
    summary: text(source.summary, 'operator artifact summary', MAX_TEXT),
    references: [...new Set(source.references.map(reference))].sort(),
    observable: normalizeObservable(source.observable),
    observation: normalizeObservation(source.observation),
  };
  const identity = stable(normalized);
  const fingerprint = hash(identity);
  return deepFreeze({
    id: `PC-${fingerprint.slice(0, 24).toUpperCase()}`,
    ...normalized,
    fingerprint,
    status: 'candidate',
  });
}

export function derivePromotionCandidates(operatorArtifacts = []) {
  if (!Array.isArray(operatorArtifacts) || operatorArtifacts.length > MAX_SOURCES) {
    throw new TypeError(`operatorArtifacts must be an array of at most ${MAX_SOURCES} records`);
  }
  const candidates = operatorArtifacts.map(normalizeSource);
  const ids = new Set();
  for (const candidate of candidates) {
    if (ids.has(candidate.id)) throw new TypeError(`duplicate promotion candidate: ${candidate.id}`);
    ids.add(candidate.id);
  }
  return deepFreeze(candidates.sort((a, b) => a.id.localeCompare(b.id)));
}

export function createPromotionState(operatorArtifacts = []) {
  return deepFreeze({
    schemaVersion: SCHEMA_VERSION,
    candidates: derivePromotionCandidates(operatorArtifacts),
    events: [],
  });
}

function validateState(state) {
  if (!state || state.schemaVersion !== SCHEMA_VERSION || !Array.isArray(state.candidates) || !Array.isArray(state.events)) {
    throw new TypeError('valid evidence promotion state is required');
  }
  if (state.candidates.length > MAX_SOURCES || state.events.length > MAX_EVENTS) throw new RangeError('promotion state exceeds bounds');
}

function eventText(value, label, max) {
  return text(value, label, max);
}

function normalizeEvent(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) throw new TypeError('promotion event must be an object');
  if (!EVENT_TYPES.has(event.type)) throw new TypeError('unsupported promotion event type');
  const common = {
    type: event.type,
    at: timestamp(event.at, 'promotion event at'),
    actorLabel: eventText(event.actorLabel, 'promotion event actorLabel', 160),
    reason: eventText(event.reason, 'promotion event reason', 1024),
  };
  let target = {};
  if (['approved', 'rejected', 'expired'].includes(event.type)) {
    const allowed = new Set(['type', 'candidateId', 'at', 'actorLabel', 'reason']);
    exactKeys(event, allowed, 'promotion event');
    target = { candidateId: eventText(event.candidateId, 'candidateId', MAX_ID) };
  } else if (event.type === 'revoked') {
    const allowed = new Set(['type', 'attestationId', 'at', 'actorLabel', 'reason']);
    exactKeys(event, allowed, 'promotion event');
    target = { attestationId: eventText(event.attestationId, 'attestationId', MAX_ID) };
  } else if (event.type === 'superseded') {
    const allowed = new Set(['type', 'candidateId', 'attestationId', 'at', 'actorLabel', 'reason']);
    exactKeys(event, allowed, 'promotion event');
    target = {
      candidateId: eventText(event.candidateId, 'candidateId', MAX_ID),
      attestationId: eventText(event.attestationId, 'attestationId', MAX_ID),
    };
  }
  const normalized = { ...common, ...target };
  return deepFreeze({ id: `PE-${hash(normalized).slice(0, 24).toUpperCase()}`, ...normalized });
}

function attestationFrom(candidate, event) {
  const core = {
    sourceArtifactId: candidate.sourceArtifactId,
    observable: candidate.observable,
    observation: candidate.observation,
    provenance: {
      sourceKind: candidate.sourceKind,
      source: candidate.source,
      capturedAt: candidate.capturedAt,
      candidateId: candidate.id,
      candidateFingerprint: candidate.fingerprint,
    },
    references: candidate.references,
    approvedAt: event.at,
    promotedAt: event.at,
    actorLabel: event.actorLabel,
    promotedBy: event.actorLabel,
    approvalReason: event.reason,
    promotionReason: event.reason,
    authority: 'analyst_promoted',
    authorityClass: 'analyst_attestation',
  };
  const fingerprint = hash(core);
  return deepFreeze({
    id: `PA-${fingerprint.slice(0, 24).toUpperCase()}`,
    ...core,
    fingerprint,
  });
}

function replay(candidates, events) {
  const candidateById = new Map(candidates.map(candidate => [candidate.id, candidate]));
  const candidateStatus = new Map(candidates.map(candidate => [candidate.id, 'candidate']));
  const attestations = new Map();
  const activeIds = new Set();
  const tupleToActive = new Map();

  for (const event of events) {
    if (['approved', 'rejected', 'expired'].includes(event.type)) {
      const candidate = candidateById.get(event.candidateId);
      if (!candidate) throw new TypeError(`promotion candidate not found: ${event.candidateId}`);
      const status = candidateStatus.get(candidate.id);
      if (status !== 'candidate') throw new TypeError(`invalid promotion transition from ${status}`);
      if (event.type === 'approved') {
        const tuple = `${candidate.sourceArtifactId}\u0000${candidate.observable.type}\u0000${candidate.observable.value}`;
        if (tupleToActive.has(tuple)) throw new TypeError('duplicate active promotion for source observable tuple');
        const attestation = attestationFrom(candidate, event);
        attestations.set(attestation.id, attestation);
        activeIds.add(attestation.id);
        tupleToActive.set(tuple, attestation.id);
        candidateStatus.set(candidate.id, 'approved');
      } else {
        candidateStatus.set(candidate.id, event.type);
      }
      continue;
    }

    const current = attestations.get(event.attestationId);
    if (!current || !activeIds.has(current.id)) throw new TypeError(`active attestation not found: ${event.attestationId}`);
    const currentTuple = `${current.sourceArtifactId}\u0000${current.observable.type}\u0000${current.observable.value}`;

    if (event.type === 'revoked') {
      activeIds.delete(current.id);
      tupleToActive.delete(currentTuple);
      continue;
    }

    const candidate = candidateById.get(event.candidateId);
    if (!candidate) throw new TypeError(`promotion candidate not found: ${event.candidateId}`);
    if (candidateStatus.get(candidate.id) !== 'candidate') throw new TypeError(`invalid promotion transition from ${candidateStatus.get(candidate.id)}`);
    const nextTuple = `${candidate.sourceArtifactId}\u0000${candidate.observable.type}\u0000${candidate.observable.value}`;
    if (nextTuple !== currentTuple) throw new TypeError('supersession must preserve source observable tuple');
    activeIds.delete(current.id);
    tupleToActive.delete(currentTuple);
    const next = attestationFrom(candidate, event);
    attestations.set(next.id, next);
    activeIds.add(next.id);
    tupleToActive.set(nextTuple, next.id);
    candidateStatus.set(candidate.id, 'approved');
  }

  return { attestations, activeIds };
}

export function deriveEffectiveAttestations(candidates = [], events = []) {
  if (!Array.isArray(candidates) || !Array.isArray(events)) throw new TypeError('candidates and events must be arrays');
  const { attestations, activeIds } = replay(candidates, events);
  return deepFreeze([...activeIds].map(id => attestations.get(id)).sort((a, b) => a.id.localeCompare(b.id)));
}

export function applyPromotionEvent(state, event) {
  validateState(state);
  if (state.events.length >= MAX_EVENTS) throw new RangeError(`promotion events exceed ${MAX_EVENTS} record limit`);
  const normalized = normalizeEvent(event);
  if (state.events.some(existing => existing.id === normalized.id)) throw new TypeError('duplicate promotion event');
  const last = state.events.at(-1);
  if (last && normalized.at < last.at) throw new TypeError('promotion events must be append-only in timestamp order');
  const events = [...state.events, normalized];
  replay(state.candidates, events);
  return deepFreeze({
    schemaVersion: SCHEMA_VERSION,
    candidates: state.candidates,
    events,
  });
}

export const EVIDENCE_PROMOTION_SCHEMA_VERSION = SCHEMA_VERSION;
