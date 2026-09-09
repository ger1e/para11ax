import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const config = JSON.parse(await readFile(new URL('../vercel.json', import.meta.url), 'utf8'));

test('the legacy route pipeline applies the deployment security policy before routing', () => {
  const rule = config.routes?.find(({ src, headers, continue: shouldContinue }) => (
    src === '/(.*)' && headers && shouldContinue === true
  ));
  assert.ok(rule, 'a continuing legacy route must cover landing, app, assets, API, and error pages');

  const headers = Object.fromEntries(
    Object.entries(rule.headers).map(([key, value]) => [key.toLowerCase(), value]),
  );
  assert.equal(headers['x-content-type-options'], 'nosniff');
  assert.equal(headers['x-frame-options'], 'DENY');
  assert.equal(headers['referrer-policy'], 'no-referrer');
  assert.equal(headers['cross-origin-opener-policy'], 'same-origin');
  assert.equal(headers['cross-origin-resource-policy'], 'same-origin');
  assert.equal(headers['permissions-policy'], 'camera=(), geolocation=(), microphone=(), payment=(), usb=()');
  assert.equal(
    headers['content-security-policy'],
    "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'",
  );
});
