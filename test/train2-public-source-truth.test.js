import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const text = path => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const json = path => JSON.parse(text(path));

const manifest = json('config/providers.json');
const capabilityCount = Object.keys(manifest).length;
const upstreamSourceCount = new Set(
  Object.entries(manifest).map(([name, policy]) => policy.providerFamily ?? name),
).size;

test('provider source truth distinguishes registered capabilities from upstream services', () => {
  assert.equal(capabilityCount, 40);
  assert.equal(upstreamSourceCount, 39);
});

test('public landing source count follows unique upstream provider families', () => {
  const landing = text('landing-maxx.html');
  assert.ok(landing.includes(`<span class="metric-value">${upstreamSourceCount}</span>`), 'landing source-count metric drift');
  assert.ok(landing.includes(`${upstreamSourceCount} FIXED SOURCES // READ-ONLY // FIXED EGRESS`), 'landing footer source-count drift');
});

test('README upstream summary and supported inputs follow source truth without forcing header metrics', () => {
  const readme = text('README.md');
  assert.ok(readme.includes(`<summary><strong>${upstreamSourceCount} upstream APIs and feeds</strong></summary>`), 'README upstream-source count drift');
  assert.match(readme, /(?:\*\*Inputs:\*\*|<strong>INPUTS<\/strong>)[^\n]*certificate/i, 'README must expose the certificate observable');
  assert.doesNotMatch(readme, /`38 FIXED SOURCES`\s*·\s*`EVIDENCE V2`/i, 'README hero/header must not restore the old metric-chip wall');
});
