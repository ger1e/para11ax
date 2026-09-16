import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

import { admitToAutomaticWorkflow, summarizeProviderBenchmark } from '../src/core/provider-admission.js';

const corpus = JSON.parse(fs.readFileSync(new URL('./fixtures/intelligence-provider-benchmark.json', import.meta.url), 'utf8'));

const REQUIRED_METRICS = Object.freeze([
  'uniqueFacts',
  'uniqueGraphEdges',
  'latencyP50Ms',
  'latencyP95Ms',
  'errorRate',
  'noResultRate',
  'decisionChangingObservations',
  'materialUniqueObservationsPerCall',
]);

const THRESHOLDS = Object.freeze({
  baseline: Object.freeze({ minUniqueFacts: 1, minMaterialUniqueObservationsPerCall: 0.1, maxLatencyP95Ms: 1500, maxErrorRate: 0.1 }),
  graph: Object.freeze({ minUniqueGraphEdges: 4, minMaterialUniqueObservationsPerCall: 0.1, maxLatencyP95Ms: 6000, maxErrorRate: 0.2 }),
});

test('benchmark summary exposes the complete deterministic provider-value metric contract', () => {
  const summary = summarizeProviderBenchmark(corpus.baselineWorthwhile.observations);
  for (const key of REQUIRED_METRICS) assert.ok(Object.hasOwn(summary, key), `missing ${key}`);
  assert.deepEqual(summary, corpus.baselineWorthwhile.expectedMetrics);
  assert.ok(Object.isFrozen(summary));
});

test('duplicative provider with zero unique facts fails automatic admission', () => {
  const metrics = summarizeProviderBenchmark(corpus.duplicative.observations);
  const decision = admitToAutomaticWorkflow(metrics, THRESHOLDS);
  assert.equal(decision.baseline.admitted, false);
  assert.equal(decision.graph.admitted, false);
  assert.ok(decision.baseline.reasons.includes('insufficient_unique_facts'));
  assert.ok(decision.graph.reasons.includes('insufficient_unique_graph_edges'));
});

test('slow high-yield graph provider may pass graph admission without entering baseline fanout', () => {
  const metrics = summarizeProviderBenchmark(corpus.slowGraphYield.observations);
  const decision = admitToAutomaticWorkflow(metrics, THRESHOLDS);
  assert.equal(decision.baseline.admitted, false);
  assert.ok(decision.baseline.reasons.includes('latency_p95_exceeds_limit'));
  assert.equal(decision.graph.admitted, true);
});

test('baseline-worthy provider passes both value and reliability gates', () => {
  const metrics = summarizeProviderBenchmark(corpus.baselineWorthwhile.observations);
  const decision = admitToAutomaticWorkflow(metrics, THRESHOLDS);
  assert.equal(decision.baseline.admitted, true);
});

test('benchmark decisions are pure and never mutate metrics thresholds or production routing inputs', () => {
  const metrics = summarizeProviderBenchmark(corpus.baselineWorthwhile.observations);
  const thresholds = structuredClone(THRESHOLDS);
  const routing = Object.freeze(['rdap', 'threatfox', 'urlscan']);
  const beforeMetrics = structuredClone(metrics);
  const beforeThresholds = structuredClone(thresholds);
  const decision = admitToAutomaticWorkflow(metrics, thresholds);
  assert.deepEqual(metrics, beforeMetrics);
  assert.deepEqual(thresholds, beforeThresholds);
  assert.deepEqual(routing, ['rdap', 'threatfox', 'urlscan']);
  assert.ok(Object.isFrozen(decision));
});
