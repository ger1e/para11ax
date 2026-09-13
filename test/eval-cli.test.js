import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const CLI = join(ROOT, 'scripts', 'run-evals.mjs');
const BASELINE = join(ROOT, 'evals', 'fixtures', 'candidate-results', 'baseline-v1.json');
const IMPROVED = join(ROOT, 'evals', 'fixtures', 'candidate-results', 'improved-v1.json');
const PRIVATE_MARKER = 'PRIVATE-MARKER-ULTRAVIOLET-9F4E';

function run(args) {
  return spawnSync(process.execPath, [CLI, ...args], {
    cwd: ROOT,
    encoding: 'utf8',
    env: { ...process.env },
  });
}

test('verify-corpus succeeds without a result bundle', () => {
  const result = run(['--verify-corpus']);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /corpus verified/i);
});

test('malformed result input exits 2', () => {
  const dir = mkdtempSync(join(tmpdir(), 'para11ax-eval-cli-'));
  try {
    const path = join(dir, 'malformed.json');
    writeFileSync(path, '{not-json', 'utf8');
    const result = run(['--results', path]);
    assert.equal(result.status, 2);
    assert.notEqual(result.stderr.trim(), '');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('json output is a parseable deterministic scorecard with no raw marker leakage', () => {
  const result = run(['--results', BASELINE, '--json']);
  assert.equal(result.status, 0, result.stderr);
  const scorecard = JSON.parse(result.stdout);
  assert.equal(scorecard.schemaVersion, 'para11ax-eval-scorecard-v1.0');
  assert.equal(scorecard.corpus.corpusId, 'para11ax-internal-v1');
  assert.doesNotMatch(result.stdout, new RegExp(PRIVATE_MARKER));
});

test('baseline comparison exposes promotion result and the 20 percent token-efficiency path', () => {
  const result = run(['--results', IMPROVED, '--baseline', BASELINE, '--json']);
  assert.equal(result.status, 0, result.stderr);
  const comparison = JSON.parse(result.stdout);
  assert.equal(comparison.schemaVersion, 'para11ax-eval-comparison-v1.0');
  assert.equal(comparison.promotion.passed, true);
  assert.equal(comparison.efficiency.totalTokenReductionRatio, 0.2);
  assert.doesNotMatch(result.stdout, new RegExp(PRIVATE_MARKER));
});

test('require-promotion exits 3 when a valid comparison fails promotion', () => {
  const result = run(['--results', BASELINE, '--baseline', BASELINE, '--require-promotion', '--json']);
  assert.equal(result.status, 3, result.stderr);
  const comparison = JSON.parse(result.stdout);
  assert.equal(comparison.promotion.required, true);
  assert.equal(comparison.promotion.passed, false);
  assert.ok(comparison.promotion.reasons.includes('INSUFFICIENT_QUALITY_OR_EFFICIENCY_GAIN'));
});

test('unknown flags exit 2', () => {
  const result = run(['--wat']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /unknown flag/i);
});

test('missing results exit 2 unless verifying the corpus', () => {
  const result = run([]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /--results/i);
});
