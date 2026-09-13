import { readFileSync } from 'node:fs';
import { isAbsolute, join, normalize, sep } from 'node:path';

import { sha256Canonical } from './canonical.js';
import {
  CORPUS_MANIFEST_SCHEMA,
  EVAL_DOMAINS,
  deepFreeze,
  validateEvalCase,
} from './schemas.js';

const MANIFEST_KEYS = Object.freeze([
  'schemaVersion',
  'corpusId',
  'corpusVersion',
  'releasedAt',
  'weights',
  'scorerVersions',
  'promotionPolicy',
  'cases',
  'corpusHash',
]);

const CASE_DESCRIPTOR_KEYS = Object.freeze(['caseId', 'domain', 'path', 'sha256']);
const PROMOTION_POLICY_KEYS = Object.freeze([
  'provenanceMaxRegression',
  'handoffMaxRegression',
  'kqlMaxRegression',
  'minimumWeightedImprovement',
  'maximumWeightedRegressionForEfficiency',
  'minimumEfficiencyReductionRatio',
  'requireHumanReviewComplete',
]);

function object(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError(`${label} must be a plain object`);
  }
  return value;
}

function exactKeys(value, expected, label) {
  const actual = Object.keys(object(value, label)).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new TypeError(`${label} has unexpected keys`);
  }
}

function nonEmptyString(value, label) {
  if (typeof value !== 'string' || value.trim() === '') throw new TypeError(`${label} must be a non-empty string`);
  return value;
}

function validateSafeRelativePath(value) {
  nonEmptyString(value, 'case path');
  if (isAbsolute(value) || value.includes('\\') || value.split('/').includes('..') || value.startsWith('/')) {
    throw new TypeError(`case path is unsafe: ${value}`);
  }
  const normalized = normalize(value).split(sep).join('/');
  if (normalized !== value || value === 'manifest.json') throw new TypeError(`case path is unsafe: ${value}`);
  return value;
}

function validateWeights(weights) {
  exactKeys(weights, EVAL_DOMAINS, 'weights');
  let sum = 0;
  for (const domain of EVAL_DOMAINS) {
    const value = weights[domain];
    if (!Number.isFinite(value) || value <= 0) throw new TypeError(`weights.${domain} must be finite and greater than zero`);
    sum += value;
  }
  if (Math.abs(sum - 1) > 1e-9) throw new TypeError('weights must sum to 1');
}

function validateScorerVersions(scorerVersions) {
  exactKeys(scorerVersions, EVAL_DOMAINS, 'scorerVersions');
  for (const domain of EVAL_DOMAINS) nonEmptyString(scorerVersions[domain], `scorerVersions.${domain}`);
}

function finiteRatio(value, label) {
  if (!Number.isFinite(value) || value < 0 || value > 1) throw new TypeError(`${label} must be a finite ratio from 0 to 1`);
}

function validatePromotionPolicy(policy) {
  exactKeys(policy, PROMOTION_POLICY_KEYS, 'promotionPolicy');
  finiteRatio(policy.provenanceMaxRegression, 'promotionPolicy.provenanceMaxRegression');
  finiteRatio(policy.handoffMaxRegression, 'promotionPolicy.handoffMaxRegression');
  finiteRatio(policy.kqlMaxRegression, 'promotionPolicy.kqlMaxRegression');
  finiteRatio(policy.minimumWeightedImprovement, 'promotionPolicy.minimumWeightedImprovement');
  finiteRatio(policy.maximumWeightedRegressionForEfficiency, 'promotionPolicy.maximumWeightedRegressionForEfficiency');
  finiteRatio(policy.minimumEfficiencyReductionRatio, 'promotionPolicy.minimumEfficiencyReductionRatio');
  if (typeof policy.requireHumanReviewComplete !== 'boolean') {
    throw new TypeError('promotionPolicy.requireHumanReviewComplete must be boolean');
  }
}

function manifestHashValue(manifest) {
  const { corpusHash: _ignored, ...rest } = manifest;
  return {
    ...rest,
    cases: [...rest.cases].sort((a, b) => a.caseId.localeCompare(b.caseId)),
  };
}

function validateDescriptor(value) {
  exactKeys(value, CASE_DESCRIPTOR_KEYS, 'case descriptor');
  nonEmptyString(value.caseId, 'case descriptor caseId');
  if (!EVAL_DOMAINS.includes(value.domain)) throw new TypeError('case descriptor domain is unsupported');
  validateSafeRelativePath(value.path);
  if (!/^sha256:[a-f0-9]{64}$/.test(value.sha256)) throw new TypeError('case descriptor sha256 is invalid');
}

function validateManifestShape(manifest) {
  exactKeys(manifest, MANIFEST_KEYS, 'corpus manifest');
  if (manifest.schemaVersion !== CORPUS_MANIFEST_SCHEMA) throw new TypeError('corpus manifest schemaVersion is unsupported');
  nonEmptyString(manifest.corpusId, 'corpusId');
  nonEmptyString(manifest.corpusVersion, 'corpusVersion');
  nonEmptyString(manifest.releasedAt, 'releasedAt');
  validateWeights(manifest.weights);
  validateScorerVersions(manifest.scorerVersions);
  validatePromotionPolicy(manifest.promotionPolicy);
  if (!Array.isArray(manifest.cases)) throw new TypeError('corpus manifest cases must be an array');
  for (const descriptor of manifest.cases) validateDescriptor(descriptor);
  if (!/^sha256:[a-f0-9]{64}$/.test(manifest.corpusHash)) throw new TypeError('corpusHash is invalid');
}

function ensureCompleteDomains(descriptors) {
  if (descriptors.length !== EVAL_DOMAINS.length) throw new TypeError('v1 corpus must contain exactly one case per domain');
  const counts = new Map(EVAL_DOMAINS.map(domain => [domain, 0]));
  for (const descriptor of descriptors) counts.set(descriptor.domain, (counts.get(descriptor.domain) ?? 0) + 1);
  for (const [domain, count] of counts) {
    if (count !== 1) throw new TypeError(`v1 corpus domain ${domain} must contain exactly one case`);
  }
}

export function buildCorpusManifest({
  corpusId,
  corpusVersion,
  releasedAt,
  weights,
  scorerVersions,
  promotionPolicy,
  cases,
}) {
  nonEmptyString(corpusId, 'corpusId');
  nonEmptyString(corpusVersion, 'corpusVersion');
  nonEmptyString(releasedAt, 'releasedAt');
  validateWeights(weights);
  validateScorerVersions(scorerVersions);
  validatePromotionPolicy(promotionPolicy);
  if (!Array.isArray(cases)) throw new TypeError('cases must be an array');

  const paths = new Set();
  const ids = new Set();
  const descriptors = cases.map(entry => {
    exactKeys(entry, ['path', 'value'], 'case entry');
    validateSafeRelativePath(entry.path);
    if (paths.has(entry.path)) throw new TypeError(`duplicate case path: ${entry.path}`);
    paths.add(entry.path);
    const value = validateEvalCase(entry.value);
    if (ids.has(value.caseId)) throw new TypeError(`duplicate caseId: ${value.caseId}`);
    ids.add(value.caseId);
    return {
      caseId: value.caseId,
      domain: value.domain,
      path: entry.path,
      sha256: sha256Canonical(value),
    };
  }).sort((a, b) => a.caseId.localeCompare(b.caseId));

  ensureCompleteDomains(descriptors);

  const draft = {
    schemaVersion: CORPUS_MANIFEST_SCHEMA,
    corpusId,
    corpusVersion,
    releasedAt,
    weights: structuredClone(weights),
    scorerVersions: structuredClone(scorerVersions),
    promotionPolicy: structuredClone(promotionPolicy),
    cases: descriptors,
    corpusHash: 'sha256:'.padEnd(71, '0'),
  };
  draft.corpusHash = sha256Canonical(manifestHashValue(draft));
  return deepFreeze(draft);
}

export function verifyCorpus({ manifest, casesByPath }) {
  validateManifestShape(manifest);
  object(casesByPath, 'casesByPath');

  const paths = new Set();
  const ids = new Set();
  const cases = [];
  for (const descriptor of manifest.cases) {
    if (paths.has(descriptor.path)) throw new TypeError(`duplicate case path: ${descriptor.path}`);
    if (ids.has(descriptor.caseId)) throw new TypeError(`duplicate caseId: ${descriptor.caseId}`);
    paths.add(descriptor.path);
    ids.add(descriptor.caseId);
    if (!Object.hasOwn(casesByPath, descriptor.path)) throw new TypeError(`missing case file: ${descriptor.path}`);
    const value = validateEvalCase(casesByPath[descriptor.path]);
    if (value.caseId !== descriptor.caseId || value.domain !== descriptor.domain) {
      throw new TypeError(`case descriptor mismatch: ${descriptor.path}`);
    }
    const actualHash = sha256Canonical(value);
    if (actualHash !== descriptor.sha256) throw new TypeError(`case hash mismatch: ${descriptor.path}`);
    cases.push(value);
  }
  ensureCompleteDomains(manifest.cases);

  const expectedHash = sha256Canonical(manifestHashValue(manifest));
  if (manifest.corpusHash !== expectedHash) throw new TypeError('corpusHash mismatch');

  return deepFreeze({
    manifest: structuredClone(manifest),
    cases: cases.sort((a, b) => a.caseId.localeCompare(b.caseId)),
  });
}

export function loadCorpusDirectory(rootPath) {
  nonEmptyString(rootPath, 'rootPath');
  const manifest = JSON.parse(readFileSync(join(rootPath, 'manifest.json'), 'utf8'));
  validateManifestShape(manifest);
  const casesByPath = {};
  for (const descriptor of manifest.cases) {
    validateSafeRelativePath(descriptor.path);
    casesByPath[descriptor.path] = JSON.parse(readFileSync(join(rootPath, descriptor.path), 'utf8'));
  }
  return verifyCorpus({ manifest, casesByPath });
}
