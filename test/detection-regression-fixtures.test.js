import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const path = new URL('./fixtures/detection-regression/cases.json', import.meta.url);
const cases = JSON.parse(readFileSync(path, 'utf8'));
const allowedClasses = new Set(['positive', 'negative', 'fp', 'boundary', 'telemetry_missing']);
const allowedOutcomes = new Set(['DETECT', 'NO_ALERT', 'TUNE', 'REVIEW', 'CANNOT_OBSERVE']);
const forbiddenKeys = /client|customer|tenant|username|hostname|indicator|credential|secret|token|password/i;

function walkKeys(value, pathParts = []) {
  if (Array.isArray(value)) return value.flatMap((entry, index) => walkKeys(entry, [...pathParts, String(index)]));
  if (!value || typeof value !== 'object') return [];
  return Object.entries(value).flatMap(([key, child]) => [[...pathParts, key].join('.'), ...walkKeys(child, [...pathParts, key])]);
}

test('detection regression fixture corpus is bounded, unique and complete', () => {
  assert.ok(Array.isArray(cases));
  assert.equal(cases.length, 5);
  assert.equal(new Set(cases.map(entry => entry.id)).size, cases.length);
  assert.deepEqual(new Set(cases.map(entry => entry.caseClass)), allowedClasses);
});

test('every detection fixture declares telemetry and an allowed expected outcome', () => {
  for (const fixture of cases) {
    assert.match(fixture.id, /^DR-00[1-5]$/);
    assert.ok(allowedClasses.has(fixture.caseClass));
    assert.ok(allowedOutcomes.has(fixture.expectedOutcome));
    assert.ok(Array.isArray(fixture.requiredTelemetry));
    assert.ok(fixture.requiredTelemetry.length > 0);
    assert.equal(typeof fixture.scenario, 'string');
    assert.ok(fixture.scenario.length > 20);
  }
});

test('missing required telemetry is never represented as a clean verdict', () => {
  const missing = cases.find(entry => entry.caseClass === 'telemetry_missing');
  assert.ok(missing);
  assert.equal(missing.expectedOutcome, 'CANNOT_OBSERVE');
});

test('fixtures contain no client-specific or secret-shaped fields', () => {
  const keys = walkKeys(cases);
  assert.equal(keys.some(key => forbiddenKeys.test(key)), false);
  const serialized = JSON.stringify(cases);
  assert.doesNotMatch(serialized, /Bearer\s|sk-[A-Za-z0-9]|@omv\.com|MorgenFund|Borealis|Borouge/i);
});
