import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = path => readFileSync(path, 'utf8');

test('request-path provider row keeps parser label clear of source count', () => {
  const svg = read('assets/brand/para11ax-readme-architecture-v4.svg');
  assert.match(svg, /39 FIXED SOURCES<\/text><text x="300" y="70"/i);
});

test('semantic vulnerability axes use separate rows instead of one collision-prone line', () => {
  const svg = read('assets/brand/para11ax-readme-semantics-v4.svg');
  assert.match(svg, /KEV = EXPLOITED<\/text><text x="20" y="100"[^>]*>EPSS = PROBABILITY<\/text><text x="350" y="100"[^>]*>CVSS = SEVERITY/i);
  assert.doesNotMatch(svg, /x="247" y="72"[^>]*>EPSS = PROBABILITY/i);
});
