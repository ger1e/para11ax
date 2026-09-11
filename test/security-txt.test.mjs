import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const SECURITY_TXT_PATH = '.well-known/security.txt';
const CANONICAL = 'https://para11ax.vercel.app/.well-known/security.txt';

test('security.txt is present with bounded RFC 9116 disclosure metadata', () => {
  const text = readFileSync(SECURITY_TXT_PATH, 'utf8');

  assert.match(text, /^Contact: https:\/\/github\.com\/ger1e\/para11ax\/security\/advisories\/new$/m);
  assert.match(text, /^Policy: https:\/\/github\.com\/ger1e\/para11ax\/blob\/main\/SECURITY\.md$/m);
  assert.match(text, new RegExp(`^Canonical: ${CANONICAL.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'm'));
  assert.match(text, /^Preferred-Languages: en$/m);
  assert.match(text, /^Expires: 2027-09-10T23:59:59Z$/m);
  assert.doesNotMatch(text, /(?:API_KEY|TOKEN|SECRET|PRIVATE KEY)=?\S+/i);
});

test('vercel routes security.txt before the catch-all 404', () => {
  const config = JSON.parse(readFileSync('vercel.json', 'utf8'));
  const securityRouteIndex = config.routes.findIndex((route) => route.src === '/\\.well-known/security\\.txt');
  const catchAllIndex = config.routes.findIndex((route) => route.src === '/.*');

  assert.notEqual(securityRouteIndex, -1);
  assert.notEqual(catchAllIndex, -1);
  assert.ok(securityRouteIndex < catchAllIndex);
  assert.equal(config.routes[securityRouteIndex].dest, '/.well-known/security.txt');
});
