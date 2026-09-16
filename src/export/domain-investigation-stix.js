import { toStixBundle, uuidV5 } from './stix.js';

const MAX_OBJECTS = 100;

function assertArtifact(artifact) {
  if (!artifact || artifact.schemaVersion !== 'domain-investigation-v1.0' || artifact.target?.type !== 'domain' || !Array.isArray(artifact.iocs) || !artifact._authoritative?.enrichment) {
    throw new TypeError('Domain Investigation v1 artifact required');
  }
}

function evidenceForIoc(artifact, ioc) {
  const fingerprints = new Set(Array.isArray(ioc.evidenceFingerprints) ? ioc.evidenceFingerprints : []);
  if (!fingerprints.size) return [];
  return (artifact._authoritative.enrichment.evidence ?? []).filter(item => fingerprints.has(item?.integrity?.fingerprint));
}

function syntheticEnrichment(artifact, ioc) {
  return {
    schemaVersion: 'evidence-v2.0',
    gatewayVersion: artifact._authoritative.enrichment.gatewayVersion ?? 'domain-investigation-v1',
    requestId: `${artifact._authoritative.enrichment.requestId ?? 'domain-investigation'}:${ioc.type}:${ioc.value}`,
    indicator: ioc.value,
    type: ioc.type,
    queriedAt: artifact.passive?.queriedAt ?? artifact._authoritative.enrichment.queriedAt ?? '1970-01-01T00:00:00.000Z',
    evidence: evidenceForIoc(artifact, ioc),
    relationships: [],
  };
}

function supported(ioc) {
  return ['domain', 'url', 'ip', 'hash', 'asn', 'cve'].includes(ioc?.type);
}

export function toDomainInvestigationStix(artifact, { maxObjects = MAX_OBJECTS } = {}) {
  assertArtifact(artifact);
  if (!Number.isInteger(maxObjects) || maxObjects < 1 || maxObjects > MAX_OBJECTS) {
    throw new TypeError('maxObjects must be between 1 and 100');
  }

  const timestamp = artifact.passive?.queriedAt ?? artifact._authoritative.enrichment.queriedAt ?? '1970-01-01T00:00:00.000Z';
  const byId = new Map();
  for (const ioc of artifact.iocs) {
    if (!supported(ioc)) continue;
    const bundle = toStixBundle(syntheticEnrichment(artifact, ioc), {
      maxObjects: 1,
      now: () => timestamp,
    });
    for (const object of bundle.objects) {
      if (!byId.has(object.id)) byId.set(object.id, object);
      if (byId.size >= maxObjects) break;
    }
    if (byId.size >= maxObjects) break;
  }

  const objects = [...byId.values()].sort((a, b) => a.id.localeCompare(b.id)).slice(0, maxObjects);
  const identity = objects.map(object => object.id).join('|') || `${artifact.target.type}:${artifact.target.value}`;
  return {
    type: 'bundle',
    id: `bundle--${uuidV5(`para11ax-domain-investigation-stix\u0000${identity}`)}`,
    objects,
  };
}
