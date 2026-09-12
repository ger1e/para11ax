import test from 'node:test';
import assert from 'node:assert/strict';

import { runFullMcpConformance } from '../src/mcp/ga-conformance.js';

const ENRICHMENT = {
  schemaVersion: '2.0',
  requestId: 'request-live-shape',
  type: 'ip',
  indicator: '1.1.1.1',
  status: 'partial',
  evidence: [],
  relationships: [],
  failures: [],
};

test('investigation transport exceptions identify the exact bounded dispatch step', async () => {
  let revision = 0;
  const invoke = async (name, args = {}) => {
    if (name !== 'para11ax_investigation') throw new Error('unrelated_surface');
    if (args.operation === 'create') {
      revision = 0;
      return { investigation: { id: 'inv-diagnostic', revision } };
    }
    if (args.operation === 'dispatch' && args.action?.type === 'EVIDENCE_CAPTURE') {
      throw new Error('mcp_ga_para11ax_investigation_transport_failed');
    }
    if (args.operation === 'dispatch') {
      revision += 1;
      return { investigation: { ...args.investigation, revision } };
    }
    return { investigation: args.investigation ?? { id: 'inv-diagnostic', revision } };
  };

  const result = await runFullMcpConformance({
    invoke,
    enrichment: ENRICHMENT,
    userScanner: { totalScanned: 1, found: 0, errors: 0 },
    now: () => '2026-09-12T10:00:00.000Z',
  });

  assert.equal(result.surfaces.para11ax_investigation.status, 'fail');
  assert.equal(
    result.surfaces.para11ax_investigation.error,
    'investigation_dispatch_evidence_capture_transport',
  );
  assert.match(result.surfaces.para11ax_investigation.error, /^[a-z0-9_:-]{1,64}$/);
});
