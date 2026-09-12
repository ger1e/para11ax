import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const workflow = readFileSync(new URL('../.github/workflows/production-mcp-smoke.yml', import.meta.url), 'utf8');

test('production MCP smoke emits bounded per-surface conformance error codes', () => {
  assert.match(workflow, /INV_ERROR=\\\(\.conformance\.surfaces\.para11ax_investigation\.error \/\/ "none"\\\)/);
  assert.match(workflow, /REPORT_ERROR=\\\(\.conformance\.surfaces\.para11ax_report\.error \/\/ "none"\\\)/);
  assert.doesNotMatch(workflow, /cat\s+["']?\$?\{?response_file/i);
});
