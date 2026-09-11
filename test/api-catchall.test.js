import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import handler from '../api/para11ax/[...path].js';

function fakeResponse() {
  return {
    statusCode: 0,
    headers: {},
    body: '',
    setHeader(name, value) { this.headers[String(name).toLowerCase()] = value; },
    end(value) { this.body = value; },
  };
}

function countJsFiles(directory) {
  let count = 0;
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) count += countJsFiles(path);
    else if (entry.isFile() && entry.name.endsWith('.js')) count += 1;
  }
  return count;
}

test('unknown API routes fail closed as JSON by default', async () => {
  const req = { method: 'GET', headers: { accept: 'application/json' }, url: '/api/para11ax/nope' };
  const res = fakeResponse();
  await handler(req, res);
  assert.equal(res.statusCode, 404);
  assert.equal(res.headers['cache-control'], 'no-store');
  assert.equal(res.headers['content-type'], 'application/json; charset=utf-8');
  const body = JSON.parse(res.body);
  assert.equal(body.error, 'not_found');
  assert.match(body.requestId, /^[0-9a-f-]{36}$/i);
});

test('unknown API routes render the branded 404 for browser clients', async () => {
  const req = { method: 'GET', headers: { accept: 'text/html' }, url: '/api/para11ax/nope' };
  const res = fakeResponse();
  await handler(req, res);
  assert.equal(res.statusCode, 404);
  assert.equal(res.headers['content-type'], 'text/html; charset=utf-8');
  assert.match(res.body, /ROUTE NOT FOUND/);
  assert.match(res.body, /FAIL CLOSED/);
});

test('signed self-test is multiplexed through the existing catch-all function', async () => {
  const req = { method: 'GET', headers: { accept: 'application/json' }, url: '/api/para11ax/self-test' };
  const res = fakeResponse();
  await handler(req, res);
  assert.equal(res.statusCode, 503);
  assert.equal(res.headers['cache-control'], 'no-store');
  assert.deepEqual(JSON.parse(res.body), { error: 'self_test_unconfigured' });
});

test('Vercel API source stays within the Hobby twelve-function ceiling', () => {
  assert.ok(countJsFiles(new URL('../api/', import.meta.url)) <= 12);
});
