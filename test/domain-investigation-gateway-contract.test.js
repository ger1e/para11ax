import test from 'node:test';
import assert from 'node:assert/strict';

import { createDomainInvestigation } from '../src/core/domain-investigation.js';
import { EVIDENCE_SCHEMA_VERSION } from '../src/core/version.js';

test('Domain Investigation accepts the canonical gateway Evidence v2 schema version', () => {
  assert.equal(EVIDENCE_SCHEMA_VERSION, '2.0');

  const artifact = createDomainInvestigation({
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    gatewayVersion: '2.0.0',
    requestId: 'gateway-contract',
    indicator: 'suspicious.example',
    type: 'domain',
    queriedAt: '2026-09-13T16:45:00.000Z',
    profile: 'standard',
    status: 'ok',
    evidence: [],
    relationships: [],
    coverage: {},
    limitations: [],
    failures: [],
    huntContext: {
      indicator: 'suspicious.example',
      type: 'domain',
      firstSeen: null,
      lastSeen: null,
      families: [],
      actors: [],
      sourceReferences: [],
    },
  });

  assert.equal(artifact.schemaVersion, 'domain-investigation-v1.0');
  assert.deepEqual(artifact.target, { type: 'domain', value: 'suspicious.example' });
});
