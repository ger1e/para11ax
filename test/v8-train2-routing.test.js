import test from 'node:test';
import assert from 'node:assert/strict';
import { semanticClass } from '../src/core/semantics.js';
import { buildDecisionSupport } from '../src/core/decision-engine.js';
import { ALL_PROVIDERS } from '../src/providers/index.js';
import { WORKFLOWS, WORKFLOW_CALL_LIMITS } from '../src/workflows.js';

test('Train 2 activates exactly 39 providers and nine bounded server workflows', () => {
  assert.equal(ALL_PROVIDERS.length, 39);
  assert.equal(Object.keys(WORKFLOWS).length, 9);
  assert.deepEqual(WORKFLOWS.certificate, ['censys', 'virustotal']);
  assert.equal(WORKFLOW_CALL_LIMITS.certificate, WORKFLOWS.certificate.length * 2);
  assert.equal(WORKFLOWS.domain[1], 'cloudflare-dns');
  assert.equal(WORKFLOW_CALL_LIMITS.domain, WORKFLOWS.domain.length * 2);
});

test('certificate and DNS observations remain contextual rather than reputation evidence', () => {
  assert.equal(semanticClass('certificate_metadata'), 'certificate_context');
  assert.equal(semanticClass('dns_resolution'), 'network_context');
});

test('certificate subject telemetry stays conditional and does not manufacture a direct KQL hunt', () => {
  const out = buildDecisionSupport({
    indicator: `cert-sha256:${'a'.repeat(64)}`,
    type: 'certificate',
    evidence: [{
      provider: 'censys',
      observation: { kind: 'certificate_metadata', verdict: 'observed', attributes: { sha256: 'a'.repeat(64) } },
      integrity: { fingerprint: 'b'.repeat(64) },
      retrievedAt: '2026-08-29T00:00:00Z',
    }],
    relationships: [],
    correlation: {
      evidenceQuality: { level: 'low', evidenceCount: 1, providerCount: 1, currentCount: 0, agingCount: 0, staleCount: 0, unknownFreshnessCount: 1, contradictionCount: 0 },
      threatAssessment: { state: 'insufficient', assessmentBasis: { providers: [], semanticClasses: [] } },
      freshness: { overall: 'unknown', items: [] },
      huntability: { level: 'none', reason: 'context_only' },
      contradictions: [],
      limitations: ['infrastructure_only_evidence'],
    },
    coverage: { materialLoss: false },
    limitations: ['infrastructure_only_evidence'],
    now: '2026-08-29T00:00:00Z',
  });
  assert.equal(out.telemetry.status, 'conditional');
  assert.deepEqual(out.telemetry.requiredTables, []);
  assert.deepEqual(out.huntPlan, []);
});
