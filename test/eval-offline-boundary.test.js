import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const EVAL_ROOT = join(ROOT, 'src', 'eval');
const CLI = join(ROOT, 'scripts', 'run-evals.mjs');

const FORBIDDEN_MODULES = new Set([
  'node:http',
  'node:https',
  'http',
  'https',
  'undici',
  'axios',
  'got',
  'openai',
  '@anthropic-ai/sdk',
  '@anthropic',
]);

function filesUnder(path) {
  const out = [];
  for (const name of readdirSync(path).sort()) {
    const child = join(path, name);
    if (statSync(child).isDirectory()) out.push(...filesUnder(child));
    else if (name.endsWith('.js') || name.endsWith('.mjs')) out.push(child);
  }
  return out;
}

function importedModules(source) {
  const modules = [];
  const patterns = [
    /\bfrom\s*['"]([^'"]+)['"]/g,
    /\bimport\s*['"]([^'"]+)['"]/g,
    /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) modules.push(match[1]);
  }
  return modules;
}

test('eval subsystem and CLI remain offline with no network/provider client imports', () => {
  const files = [...filesUnder(EVAL_ROOT), CLI];
  assert.ok(files.length > 10, 'offline boundary must cover the complete eval subsystem');

  for (const path of files) {
    const source = readFileSync(path, 'utf8');
    const label = relative(ROOT, path).replaceAll('\\', '/');
    for (const specifier of importedModules(source)) {
      assert.equal(
        FORBIDDEN_MODULES.has(specifier) || specifier.startsWith('@anthropic/'),
        false,
        `${label} must not import network/model client ${specifier}`,
      );
    }
    assert.doesNotMatch(source, /\bfetch\s*\(/, `${label} must not perform fetch egress`);
    assert.doesNotMatch(source, /\bXMLHttpRequest\b/, `${label} must not use XMLHttpRequest`);
    assert.doesNotMatch(source, /\bWebSocket\b/, `${label} must not use WebSocket egress`);
  }
});
