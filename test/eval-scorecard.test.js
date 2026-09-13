import test from 'node:test';
import assert from 'node:assert/strict';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../src/eval/canonical.js';
import { loadCorpusDirectory } from '../src/eval/corpus.js';
import {
  assertAggregateOnlyScorecard,
  scoreResultBundle,
} from '../src/eval/index.js';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const corpus = loadCorpusDirectory(join(ROOT, 'evals/corpus/v1'));
const PRIVATE_MARKER = 'PRIVATE-MARKER-ULTRAVIOLET-9F4E';

function perfectOutput(caseId) {
  switch (caseId) {
    case 'cti-001':
      return {
        entities: ['actor:ORCHID', 'malware:TEST-RAT', 'cve:CVE-2026-12345'],
        relationships: ['uses:ORCHID:TEST-RAT', 'exploits:TEST-RAT:CVE-2026-12345'],
        note: PRIVATE_MARKER,
      };
    case 'provenance-001':
      return { claims: [
        { claimId: 'claim-actor-malware', evidenceIds: ['ev-1'] },
        { claimId: 'claim-c2', evidenceIds: ['ev-2'] },
      ] };
    case 'classification-001':
      return { items: [
        { id: 'item-1', label: 'ioc' },
        { id: 'item-2', label: 'ioa' },
        { id: 'item-3', label: 'ttp' },
      ] };
    case 'attack-001':
      return { techniques: ['T1059.001', 'T1071.001'] };
    case 'kql-001':
      return {
        query: 'DeviceProcessEvents | where Timestamp > ago(1d) | summarize Count=count() by DeviceName',
        headers: {
          Title: 'Synthetic PowerShell hunt',
          Description: 'Synthetic case only',
          'Suspicious Behavior': 'PowerShell process activity',
          'MITRE ATT&CK': 'T1059.001',
          'Pyramid of Pain': 'TTP',
          'Kill Chain': 'Execution',
          'CTI URLs': 'https://example.invalid/cti',
        },
      };
    case 'handoff-001':
      return {
        objective: 'Complete the synthetic investigation without changing accepted scope.',
        constraints: ['Preserve provenance.', 'Do not treat missing evidence as benign.'],
        decisions: ['Use DeviceProcessEvents as the primary synthetic telemetry source.'],
        nextActions: ['validate-kql', 'analyze-results'],
        completed: false,
      };
    case 'context-001':
      return { selectedIds: ['objective', 'constraints', 'decision-1'] };
    case 'routing-001':
      return {
        tier: 'frontier',
        reasoningEffort: 'high',
        specialistHint: null,
        requireIndependentReview: true,
        requireDifferentFamilyReviewer: true,
        contextPolicy: 'durable-state-plus-jit-retrieval',
      };
    case 'coding-001':
      return { defects: ['missing-input-validation', 'nondeterministic-wall-clock'] };
    default:
      throw new Error(`unknown test case ${caseId}`);
  }
}

function resultBundle(caseOrder = corpus.cases.map(item => item.caseId)) {
  return {
    schemaVersion: 'para11ax-eval-result-v1.0',
    corpusId: corpus.manifest.corpusId,
    runId: 'baseline-run-v1',
    candidate: {
      provider: 'openai',
      model: 'synthetic-model',
      family: 'synthetic-family',
      effort: 'high',
      harness: 'offline-fixture',
      harnessVersion: '1.0.0',
    },
    measurements: {
      inputTokens: 900,
      outputTokens: 100,
      costUsd: null,
      latencyMs: null,
    },
    cases: caseOrder.map(caseId => ({
      caseId,
      output: perfectOutput(caseId),
      measurements: {},
      review: caseId === 'cti-001' ? { status: 'completed', decision: 'pass' } : null,
    })),
  };
}

test('scorecard requires the complete known corpus case set', () => {
  const missing = resultBundle().cases.slice(0, -1);
  assert.throws(() => scoreResultBundle({
    corpus,
    resultBundle: { ...resultBundle(), cases: missing },
  }), /missing|full corpus/i);

  const unknown = resultBundle();
  unknown.cases[0] = { ...unknown.cases[0], caseId: 'cti-999' };
  assert.throws(() => scoreResultBundle({ corpus, resultBundle: unknown }), /unknown|corpus/i);
});

test('scorecard is byte-identical under result-case ordering changes', () => {
  const forward = scoreResultBundle({ corpus, resultBundle: resultBundle() });
  const reversed = scoreResultBundle({
    corpus,
    resultBundle: resultBundle([...corpus.cases.map(item => item.caseId)].reverse()),
  });
  assert.equal(canonicalJson(forward), canonicalJson(reversed));
  assert.equal(forward.scorecardHash, reversed.scorecardHash);
});

test('identical input produces byte-identical canonical scorecard and hash', () => {
  const one = scoreResultBundle({ corpus, resultBundle: resultBundle() });
  const two = scoreResultBundle({ corpus, resultBundle: resultBundle() });
  assert.equal(canonicalJson(one), canonicalJson(two));
  assert.match(one.scorecardHash, /^sha256:[a-f0-9]{64}$/);
  assert.match(one.resultHash, /^sha256:[a-f0-9]{64}$/);
});

test('raw output marker never survives into scorecard serialization', () => {
  const scorecard = scoreResultBundle({ corpus, resultBundle: resultBundle() });
  const serialized = canonicalJson(scorecard);
  assert.equal(serialized.includes(PRIVATE_MARKER), false);
  assert.doesNotThrow(() => assertAggregateOnlyScorecard(scorecard));
});

test('scorecard preserves null measurements and reproducibility metadata', () => {
  const scorecard = scoreResultBundle({ corpus, resultBundle: resultBundle() });
  assert.equal(scorecard.measurements.inputTokens, 900);
  assert.equal(scorecard.measurements.outputTokens, 100);
  assert.equal(scorecard.measurements.totalTokens, 1000);
  assert.equal(scorecard.measurements.costUsd, null);
  assert.equal(scorecard.measurements.latencyMs, null);
  assert.equal(scorecard.corpus.corpusId, corpus.manifest.corpusId);
  assert.equal(scorecard.corpus.corpusVersion, corpus.manifest.corpusVersion);
  assert.equal(scorecard.corpus.corpusHash, corpus.manifest.corpusHash);
  assert.deepEqual(scorecard.corpus.scorerVersions, corpus.manifest.scorerVersions);
  assert.deepEqual(scorecard.corpus.promotionPolicy, corpus.manifest.promotionPolicy);
  assert.equal(scorecard.aggregate.scoredCases, 9);
  assert.equal(scorecard.aggregate.weightedScore, 1);
});

test('case results contain bounded review projection and never raw review/output data', () => {
  const scorecard = scoreResultBundle({ corpus, resultBundle: resultBundle() });
  const cti = scorecard.cases.find(item => item.caseId === 'cti-001');
  assert.deepEqual(Object.keys(cti).sort(), [
    'caseId', 'criticalHardFail', 'domain', 'hardFail', 'humanReview',
    'metrics', 'score', 'scorerVersion', 'violations',
  ]);
  assert.deepEqual(cti.humanReview, {
    required: false,
    fields: [],
    reviewStatus: 'not_required',
    reviewDecision: null,
  });
  assert.equal(Object.hasOwn(cti, 'output'), false);
  assert.equal(JSON.stringify(cti).includes(PRIVATE_MARKER), false);
});

test('candidate-controlled identifiers are collapsed to stable violation codes in scorecards', () => {
  const bundle = resultBundle();
  const classification = bundle.cases.find(item => item.caseId === 'classification-001');
  classification.output.items.push({ id: PRIVATE_MARKER, label: 'ioc' });
  const scorecard = scoreResultBundle({ corpus, resultBundle: bundle });
  const scored = scorecard.cases.find(item => item.caseId === 'classification-001');
  assert.ok(scored.violations.includes('CLASSIFICATION_UNEXPECTED_ITEM'));
  assert.equal(JSON.stringify(scored).includes(PRIVATE_MARKER), false);
});
