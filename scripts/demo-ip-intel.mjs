#!/usr/bin/env node
// PARA11AX meeting smoke test. Uses the real command fabric; no mock threat intelligence.
import { spawnSync } from 'node:child_process';
import assert from 'node:assert/strict';

const ip = process.argv[2] ?? '8.8.8.8';
const cli = new URL('../bin/para11ax.mjs', import.meta.url).pathname;
function run(...args) {
  const result = spawnSync(process.execPath, [cli, ...args], {
    encoding: 'utf8', timeout: 90000, maxBuffer: 2 * 1024 * 1024,
    env: process.env,
  });
  if (result.error) throw result.error;
  return result;
}
const validate = run('validate', ip);
assert.equal(validate.status, 0, validate.stderr);
console.log('┌───────────────────────────────────────────────────────────┐');
console.log('│ PARA11AX // IP INTELLIGENCE CONSOLE SMOKE TEST           │');
console.log('└───────────────────────────────────────────────────────────┘');
console.log('[PASS] Observable validation');
console.log(validate.stdout.trim());
console.log('\n[RUN] Live provider enrichment (real APIs, may need keys/network)');
const enriched = run('enrich', ip, '--fast');
if (enriched.status !== 0) {
  console.error('[WARN] Live enrichment unavailable:', enriched.stderr.trim());
  process.exitCode = 1;
} else {
  console.log('[PASS] Enrichment completed');
  console.log(enriched.stdout.trim());
}
console.log('\n[LINKS] Investigation pivots (links are NOT evidence of detections)');
for (const [name, url] of [
  ['VirusTotal', 'https://www.virustotal.com/gui/ip-address/'],
  ['AbuseIPDB', 'https://www.abuseipdb.com/check/'],
  ['GreyNoise', 'https://viz.greynoise.io/ip/'],
  ['Shodan', 'https://www.shodan.io/host/'],
]) {
  const target = url + encodeURIComponent(ip);
  const clickable = process.stdout.isTTY ? '\x1b]8;;' + target + '\x1b\\' + name + '\x1b]8;;\x1b\\' : name;
  console.log('  ' + clickable.padEnd(process.stdout.isTTY ? clickable.length : 12) + ' ' + target);
}
