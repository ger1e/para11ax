import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildCoverage, buildCorrelation } from '../app/view-model.js';
import { WORKFLOWS, WORKFLOW_CALL_LIMITS } from '../src/workflows.js';

const sample = {
  providerSummary: { ok: 19, failed: 3, skipped: 2, cached: 0 },
  failures: [
    { provider: 'feodo-tracker', reason: 'timeout', retrievedAt: '2026-08-29T20:41:09.058Z' },
    { provider: 'misp-circl-osint', reason: 'http_error', status: 502, retrievedAt: '2026-08-29T20:41:01.068Z' },
    { provider: 'webamon', reason: 'provider_call_budget_exhausted' },
  ],
  correlation: {
    freshness: 'current',
    huntability: { level: 'high', rationale: 'Actionable pivots are available.' },
    corroboration: [{ providers: ['a', 'b'], kind: 'reputation', verdict: 'observed' }],
    contradictions: [{ providers: ['c', 'd'], kind: 'reputation', note: 'sources disagree' }],
    riskAxes: { kev: { listed: true }, epss: { score: 0.94 }, cvss: { score: 9.8 } },
  },
};

test('coverage converts raw provider failures into coherent analyst facts', () => {
  const model = buildCoverage(sample);
  assert.match(model.summaryText, /19 succeeded/i);
  assert.equal(model.failures[0].provider, 'feodo-tracker');
  assert.equal(model.failures[0].state, 'failed');
  assert.match(model.failures[0].label, /timeout/i);
  assert.match(model.failures[0].summary, /provider|upstream/i);
  assert.equal(model.failures[1].status, 502);
  assert.match(model.failures[1].label, /502/);
  assert.equal(model.failures[2].state, 'skipped');
  assert.match(model.failures[2].label, /call budget/i);
  assert.match(model.failures[2].summary, /not (?:called|run)/i);
});

test('correlation exposes risk axes as readable facts rather than raw JSON blobs', () => {
  const model = buildCorrelation(sample);
  assert.equal(model.riskAxes.kev.display, 'LISTED');
  assert.equal(model.riskAxes.epss.display, '0.94');
  assert.equal(model.riskAxes.cvss.display, '9.8');
  assert.ok(Array.isArray(model.corroboration[0].facts));
  assert.ok(Array.isArray(model.contradictions[0].facts));
});

test('structured WebUI views do not JSON-dump CTI objects', () => {
  const renderers = readFileSync('app/renderers.js', 'utf8');
  const shell = readFileSync('app/shell-ui.js', 'utf8');
  assert.doesNotMatch(renderers, /coverage-failure[^\n]*JSON\.stringify|JSON\.stringify\(failure/i);
  assert.doesNotMatch(renderers, /JSON\.stringify\(item, null, 2\)/i);
  assert.doesNotMatch(renderers, /JSON\.stringify\(card\.attributes/i);
  assert.match(shell, /renderResultView\(['"]brief['"](?:\s*,\s*output\.value)?\)/i);
  assert.match(shell, /executePipeline\(ast/);
  assert.doesNotMatch(shell, /filter === ['"]failures['"][^\n]*appendJson/is);
  assert.doesNotMatch(shell, /filter === ['"]contradictions['"][^\n]*appendJson/is);
  assert.doesNotMatch(shell, /filter === ['"]corroboration['"][^\n]*appendJson/is);
});

test('explicit raw/JSON paths remain available for exact machine output', () => {
  const shell = readFileSync('app/shell-ui.js', 'utf8');
  const executor = readFileSync('app/shell-browser-executor.js', 'utf8');
  const renderers = readFileSync('app/renderers.js', 'utf8');
  assert.match(shell, /id === ['"]result\.raw['"][^\n]*renderResultView\(['"]raw['"],\s*output\.value\)/i);
  assert.match(executor, /handler === ['"]json['"]/i);
  assert.match(executor, /JSON\.stringify\(resultOrInput\(state, input\), null, 2\)/i);
  assert.match(executor, /args\[0\] === ['"]save['"][^\n]*downloads\.save/i);
  assert.match(renderers, /export function renderRaw/);
});

test('full CTI workflow budget permits at most two bounded attempts per configured workflow provider without starving later providers', () => {
  for (const [type, providers] of Object.entries(WORKFLOWS)) {
    assert.ok(
      WORKFLOW_CALL_LIMITS[type] >= providers.length * 2,
      `${type}: expected call limit >= ${providers.length * 2}, got ${WORKFLOW_CALL_LIMITS[type]}`,
    );
  }
});

test('terminal chrome reports the canonical 39-upstream-source fabric', () => {
  const polish = readFileSync('app/terminal-polish.js', 'utf8');
  assert.match(polish, /39 SOURCES/);
  assert.match(polish, /39 SRC/);
  assert.doesNotMatch(polish, /38 SOURCES|38 SRC|40 SOURCES|40 SRC/);
});

test('report renderers format structured analyst content without JSON object syntax', () => {
  const text = readFileSync('src/report/render-text.js', 'utf8');
  const html = readFileSync('src/report/render-html.js', 'utf8');
  assert.doesNotMatch(text, /JSON\.stringify\(item\)/);
  assert.doesNotMatch(html, /JSON\.stringify\(item\)/);
});
