import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { sha256Canonical } from '../src/eval/canonical.js';
import {
  buildCorpusManifest,
  loadCorpusDirectory,
  verifyCorpus,
} from '../src/eval/corpus.js';
import { CORPUS_MANIFEST_SCHEMA, EVAL_CASE_SCHEMA, EVAL_DOMAINS } from '../src/eval/schemas.js';

const weights = Object.freeze({
  provenance: 0.20,
  kql: 0.15,
  cti: 0.15,
  handoff: 0.15,
  attack: 0.10,
  classification: 0.10,
  context: 0.05,
  routing: 0.05,
  coding: 0.05,
});

const scorerVersions = Object.freeze(Object.fromEntries(EVAL_DOMAINS.map(domain => [domain, '1.0.0'])));

const promotionPolicy = Object.freeze({
  provenanceMaxRegression: 0.02,
  handoffMaxRegression: 0.02,
  kqlMaxRegression: 0.03,
  minimumWeightedImprovement: 0.02,
  maximumWeightedRegressionForEfficiency: 0.01,
  minimumEfficiencyReductionRatio: 0.20,
  requireHumanReviewComplete: true,
});

function makeCase(domain, index = 1) {
  return {
    schemaVersion: EVAL_CASE_SCHEMA,
    caseId: `${domain}-${String(index).padStart(3, '0')}`,
    domain,
    weight: 1,
    input: { marker: `${domain}-input` },
    expected: { marker: `${domain}-expected` },
  };
}

function caseEntries() {
  return EVAL_DOMAINS.map(domain => ({
    path: `${domain}/${domain}-001.json`,
    value: makeCase(domain),
  }));
}

function manifestAndCases() {
  const entries = caseEntries();
  const manifest = buildCorpusManifest({
    corpusId: 'para11ax-internal-v1',
    corpusVersion: '1.0.0',
    releasedAt: '2026-09-13',
    weights,
    scorerVersions,
    promotionPolicy,
    cases: entries,
  });
  return {
    manifest,
    casesByPath: Object.fromEntries(entries.map(entry => [entry.path, entry.value])),
  };
}

test('buildCorpusManifest creates a deterministic nine-domain manifest and policy', () => {
  const { manifest, casesByPath } = manifestAndCases();
  assert.equal(manifest.schemaVersion, CORPUS_MANIFEST_SCHEMA);
  assert.equal(manifest.corpusId, 'para11ax-internal-v1');
  assert.equal(manifest.cases.length, 9);
  assert.equal(manifest.promotionPolicy.minimumEfficiencyReductionRatio, 0.20);
  assert.match(manifest.corpusHash, /^sha256:[a-f0-9]{64}$/);
  for (const descriptor of manifest.cases) {
    assert.equal(descriptor.sha256, sha256Canonical(casesByPath[descriptor.path]));
  }
});

test('verifyCorpus accepts exactly one case per v1 domain and returns frozen data', () => {
  const { manifest, casesByPath } = manifestAndCases();
  const corpus = verifyCorpus({ manifest, casesByPath });
  assert.equal(corpus.cases.length, 9);
  assert.deepEqual(corpus.cases.map(item => item.domain).sort(), [...EVAL_DOMAINS].sort());
  assert.equal(Object.isFrozen(corpus), true);
  assert.equal(Object.isFrozen(corpus.cases), true);
});

test('verifyCorpus rejects mutation, duplicate case IDs and missing domains', () => {
  const { manifest, casesByPath } = manifestAndCases();
  const mutated = structuredClone(casesByPath);
  mutated['cti/cti-001.json'].input.marker = 'tampered';
  assert.throws(() => verifyCorpus({ manifest, casesByPath: mutated }), /hash|sha256/i);

  const duplicateManifest = structuredClone(manifest);
  duplicateManifest.cases[1].caseId = duplicateManifest.cases[0].caseId;
  assert.throws(() => verifyCorpus({ manifest: duplicateManifest, casesByPath }), /duplicate/i);

  const missingManifest = structuredClone(manifest);
  missingManifest.cases.pop();
  const missingCases = structuredClone(casesByPath);
  delete missingCases['coding/coding-001.json'];
  assert.throws(() => verifyCorpus({ manifest: missingManifest, casesByPath: missingCases }), /domain|exactly|missing/i);
});

test('corpus rejects unsafe paths, invalid weights and incomplete scorer policy', () => {
  const entries = caseEntries();
  assert.throws(() => buildCorpusManifest({
    corpusId: 'para11ax-internal-v1', corpusVersion: '1.0.0', releasedAt: '2026-09-13',
    weights, scorerVersions, promotionPolicy,
    cases: [{ ...entries[0], path: '../cti.json' }, ...entries.slice(1)],
  }), /path/i);

  assert.throws(() => buildCorpusManifest({
    corpusId: 'para11ax-internal-v1', corpusVersion: '1.0.0', releasedAt: '2026-09-13',
    weights: { ...weights, coding: 0.06 }, scorerVersions, promotionPolicy, cases: entries,
  }), /weights|sum/i);

  const incomplete = { ...scorerVersions };
  delete incomplete.routing;
  assert.throws(() => buildCorpusManifest({
    corpusId: 'para11ax-internal-v1', corpusVersion: '1.0.0', releasedAt: '2026-09-13',
    weights, scorerVersions: incomplete, promotionPolicy, cases: entries,
  }), /scorer/i);
});

test('loadCorpusDirectory reads only manifest-declared local case files', () => {
  const root = mkdtempSync(join(tmpdir(), 'para11ax-evals-'));
  const { manifest, casesByPath } = manifestAndCases();
  writeFileSync(join(root, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  for (const [relativePath, value] of Object.entries(casesByPath)) {
    const target = join(root, relativePath);
    mkdirSync(target.slice(0, target.lastIndexOf('/')), { recursive: true });
    writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  }
  writeFileSync(join(root, 'undeclared-secret.json'), '{"secret":"must-not-load"}\n', 'utf8');

  const corpus = loadCorpusDirectory(root);
  assert.equal(corpus.cases.length, 9);
  assert.equal(readFileSync(join(root, 'undeclared-secret.json'), 'utf8').includes('must-not-load'), true);
  assert.equal(JSON.stringify(corpus).includes('must-not-load'), false);
});
