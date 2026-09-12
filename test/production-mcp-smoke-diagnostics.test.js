import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const workflow = readFileSync(new URL('../.github/workflows/production-mcp-smoke.yml', import.meta.url), 'utf8');

test('production MCP smoke emits bounded per-surface conformance error codes', () => {
  assert.ok(workflow.includes('INV_ERROR=\\(.conformance.surfaces.para11ax_investigation.error // "none")'));
  assert.ok(workflow.includes('REPORT_ERROR=\\(.conformance.surfaces.para11ax_report.error // "none")'));
  assert.doesNotMatch(workflow, /cat\s+["']?\$?\{?response_file/i);
});

test('production MCP smoke emits only bounded provider failure diagnostics', () => {
  assert.ok(workflow.includes('IP_PROVIDER_FAILURES=\\((.enrichment.providerFailures // []) | map(.provider + ":" + .reason) | join(","))'));
  assert.doesNotMatch(workflow, /\.enrichment\.failures/);
  assert.doesNotMatch(workflow, /tojson|@json/);
});
