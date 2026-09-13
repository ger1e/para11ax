#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  canonicalJson,
  compareScorecards,
  loadCorpusDirectory,
  scoreResultBundle,
} from '../src/eval/index.js';

const CORPUS_ROOT = fileURLToPath(new URL('../evals/corpus/v1/', import.meta.url));
const VALUE_FLAGS = new Set(['--results', '--baseline']);
const BOOLEAN_FLAGS = new Set(['--json', '--verify-corpus', '--require-promotion']);
const ALLOWED_FLAGS = new Set([...VALUE_FLAGS, ...BOOLEAN_FLAGS]);

function usageError(message) {
  const error = new TypeError(message);
  error.exitCode = 2;
  return error;
}

function parseArgs(argv) {
  const options = {
    results: null,
    baseline: null,
    json: false,
    verifyCorpus: false,
    requirePromotion: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (!ALLOWED_FLAGS.has(flag)) throw usageError(`unknown flag: ${flag}`);

    if (VALUE_FLAGS.has(flag)) {
      const value = argv[index + 1];
      if (!value || value.startsWith('--')) throw usageError(`${flag} requires a file path`);
      if (flag === '--results') {
        if (options.results !== null) throw usageError('--results may be supplied only once');
        options.results = value;
      } else {
        if (options.baseline !== null) throw usageError('--baseline may be supplied only once');
        options.baseline = value;
      }
      index += 1;
      continue;
    }

    if (flag === '--json') options.json = true;
    else if (flag === '--verify-corpus') options.verifyCorpus = true;
    else if (flag === '--require-promotion') options.requirePromotion = true;
  }

  if (options.verifyCorpus) {
    if (options.results || options.baseline || options.requirePromotion) {
      throw usageError('--verify-corpus cannot be combined with evaluation inputs');
    }
    return options;
  }

  if (!options.results) throw usageError('--results is required unless --verify-corpus is used');
  if (options.baseline === null && options.requirePromotion) {
    throw usageError('--require-promotion requires --baseline');
  }
  return options;
}

function readJson(path, label) {
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    throw usageError(`${label} file could not be read`);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw usageError(`${label} file is not valid JSON`);
  }
}

function humanScorecard(scorecard) {
  const lines = [
    `PARA11AX eval scorecard ${scorecard.scorecardHash}`,
    `candidate: ${scorecard.candidate.provider}/${scorecard.candidate.model}`,
    `corpus: ${scorecard.corpus.corpusId}@${scorecard.corpus.corpusVersion}`,
    `weighted score: ${scorecard.aggregate.weightedScore}`,
    `hard failures: ${scorecard.aggregate.hardFailures} (${scorecard.aggregate.criticalHardFailures} critical)`,
    `human-review cases: ${scorecard.aggregate.humanReviewCases}`,
    `tokens: ${scorecard.measurements.totalTokens}`,
    `cost USD: ${scorecard.measurements.costUsd === null ? 'unknown' : scorecard.measurements.costUsd}`,
    `latency ms: ${scorecard.measurements.latencyMs === null ? 'unknown' : scorecard.measurements.latencyMs}`,
  ];
  return `${lines.join('\n')}\n`;
}

function humanComparison(comparison) {
  const lines = [
    `PARA11AX eval comparison ${comparison.baseline.scorecardHash} -> ${comparison.candidate.scorecardHash}`,
    `weighted-score delta: ${comparison.deltas.weightedScore}`,
    `hard-failure delta: ${comparison.deltas.hardFailures} (${comparison.deltas.criticalHardFailures} critical)`,
    `total-token delta: ${comparison.deltas.totalTokens}`,
    `cost delta USD: ${comparison.deltas.costUsd === null ? 'unknown' : comparison.deltas.costUsd}`,
    `latency delta ms: ${comparison.deltas.latencyMs === null ? 'unknown' : comparison.deltas.latencyMs}`,
    `promotion: ${comparison.promotion.passed ? 'PASS' : 'BLOCKED'}`,
    `promotion reasons: ${comparison.promotion.reasons.length ? comparison.promotion.reasons.join(', ') : 'none'}`,
  ];
  return `${lines.join('\n')}\n`;
}

function writeOutput(value, json, humanRenderer) {
  process.stdout.write(json ? `${canonicalJson(value)}\n` : humanRenderer(value));
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const corpus = loadCorpusDirectory(CORPUS_ROOT);

  if (options.verifyCorpus) {
    if (options.json) {
      process.stdout.write(`${canonicalJson({
        corpusHash: corpus.manifest.corpusHash,
        corpusId: corpus.manifest.corpusId,
        corpusVersion: corpus.manifest.corpusVersion,
        verifiedCases: corpus.cases.length,
      })}\n`);
    } else {
      process.stdout.write(`PARA11AX eval corpus verified: ${corpus.manifest.corpusId}@${corpus.manifest.corpusVersion} (${corpus.cases.length} cases)\n`);
    }
    return 0;
  }

  const candidateBundle = readJson(options.results, 'results');
  const candidateScorecard = scoreResultBundle({ corpus, resultBundle: candidateBundle });

  if (!options.baseline) {
    writeOutput(candidateScorecard, options.json, humanScorecard);
    return 0;
  }

  const baselineBundle = readJson(options.baseline, 'baseline');
  const baselineScorecard = scoreResultBundle({ corpus, resultBundle: baselineBundle });
  const comparison = compareScorecards({
    baseline: baselineScorecard,
    candidate: candidateScorecard,
    requirePromotion: options.requirePromotion,
  });
  writeOutput(comparison, options.json, humanComparison);
  if (options.requirePromotion && !comparison.promotion.passed) return 3;
  return 0;
}

try {
  process.exitCode = main();
} catch (error) {
  const exitCode = Number.isInteger(error?.exitCode) ? error.exitCode : 2;
  const message = error instanceof Error && error.message ? error.message : 'evaluation failed';
  process.stderr.write(`PARA11AX eval error: ${message}\n`);
  process.exitCode = exitCode;
}
