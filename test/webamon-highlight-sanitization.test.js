import test from 'node:test';
import assert from 'node:assert/strict';
import { webamonProvider } from '../src/providers/webamon.js';

function response(body) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

test('Webamon strips search highlight markup before emitting observable relationships', async () => {
  const data = await webamonProvider.run(
    { value: 'example.com', type: 'domain' },
    {
      env: { WEBAMON_API_KEY: 'qa-key' },
      signal: new AbortController().signal,
      fetchImpl: async () => response({
        total_hits: 1,
        results: [{
          domain: { name: '<mark>example.com</mark>' },
          resolved_url: 'https://<mark>example.com</mark>/',
          submission_url: 'https://example.com',
          meta: { risk_score: 1 },
        }],
      }),
    },
  );

  assert.equal(data.verdict, 'observed');
  assert.ok(data.relationships.some(item => item.targetType === 'domain' && item.target === 'example.com'));
  assert.ok(data.relationships.some(item => item.targetType === 'url' && item.target === 'https://example.com/'));
  assert.equal(data.relationships.some(item => /<\/?mark>/i.test(item.target)), false);
});
