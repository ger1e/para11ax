import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const workflow = readFileSync(new URL('../.github/workflows/production-mcp-smoke.yml', import.meta.url), 'utf8');

test('production MCP smoke uses GitHub OIDC and never duplicates the analyst bearer', () => {
  assert.match(workflow, /id-token:\s*write/);
  assert.match(workflow, /para11ax-production-smoke/);
  assert.match(workflow, /ACTIONS_ID_TOKEN_REQUEST_URL/);
  assert.match(workflow, /ACTIONS_ID_TOKEN_REQUEST_TOKEN/);
  assert.match(workflow, /https:\/\/para11ax\.vercel\.app\/api\/para11ax\/self-test/);
  assert.match(workflow, /EXPECTED_SHA:\s*\$\{\{ github\.sha \}\}/);
  assert.match(workflow, /\.deploymentSha == \$sha/);
  assert.match(workflow, /\.authorization == "github_oidc"/);
  assert.match(workflow, /\.mcp\.toolCount == 13/);
  assert.match(workflow, /\.enrichment\.target == "1\.1\.1\.1"/);
  assert.match(workflow, /\.userScanner\.target == "ger1e"/);
  assert.doesNotMatch(workflow, /secrets\.PARA11AX_TOKEN/);
  assert.doesNotMatch(workflow, /PARA11AX_ANALYST_TOKEN/);
});
