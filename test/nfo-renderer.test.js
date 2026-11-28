import test from 'node:test';
import assert from 'node:assert/strict';
import { formatNfoReport } from '../app/renderers.js';

test('NFO uses numbered scene dividers and preserves long identifiers', () => {
  const hash = 'a'.repeat(64);
  const output = formatNfoReport('HASH INTELLIGENCE REPORT\nASSESSMENT\n----------\nSHA256: ' + hash + '\n\nPROVIDER COVERAGE\n-----------------\nNo results');
  assert.match(output, /01 :: ASSESSMENT/);
  assert.match(output, /02 :: PROVIDER COVERAGE/);
  assert.match(output, /END OF INTELLIGENCE TRANSMISSION/);
  assert.ok(output.includes(hash));
  assert.ok(output.includes('░▒▓'));
});

test('NFO retains full allowlisted source URL, defangs other URLs and redacts credentials', () => {
  const source = 'https://www.virustotal.com/gui/ip-address/192.0.2.44';
  const unsafe = 'https://example.invalid/indicator';
  const spoof = 'https://virustotal.com.example.invalid/path';
  const secret = 'https://www.virustotal.com/gui/?api_key=do-not-copy';
  const output = formatNfoReport([
    'SOURCE REFERENCES','-----------------',
    'SOURCE 1: ' + source,
    'SOURCE 2: ' + unsafe,
    'SOURCE 3: ' + spoof,
    'SOURCE 4: ' + secret,
    'COMMENT: ' + source,
  ].join('\n'), [source, unsafe, spoof, secret]);
  assert.ok(output.includes('SOURCE 1: ' + source));
  assert.ok(output.includes('hxxps://example.invalid/indicator'));
  assert.ok(output.includes('hxxps://virustotal.com.example.invalid/path'));
  assert.ok(output.includes('[REDACTED URL]'));
  assert.ok(!output.includes('do-not-copy'));
  assert.ok(output.includes('hxxps://www.virustotal.com/gui/ip-address/192.0.2.44'));
});

test('NFO strips terminal control and bidirectional override characters', () => {
  const result = formatNfoReport('untrusted\x1b[31m\u202e text');
  assert.ok(!result.includes('\x1b'));
  assert.ok(!result.includes('\u202e'));
});
