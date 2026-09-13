import test from 'node:test';
import assert from 'node:assert/strict';

import { hibpProvider } from '../src/providers/hibp.js';
import { hudsonRockProvider } from '../src/providers/hudson-rock.js';
import { spyCloudProvider } from '../src/providers/spycloud.js';

function json(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const SECRET_SENTINELS = [
  'PLAINTEXT-PASSWORD-DO-NOT-KEEP',
  'SESSION-COOKIE-DO-NOT-KEEP',
  'ACCESS-TOKEN-DO-NOT-KEEP',
];

function assertNoSecretSentinels(value) {
  const serialized = JSON.stringify(value);
  for (const sentinel of SECRET_SENTINELS) assert.equal(serialized.includes(sentinel), false, sentinel);
}

test('HIBP account lookup is bounded and keeps breach metadata but not credentials', async () => {
  let calls = 0;
  const output = await hibpProvider.run({ type: 'email', value: 'analyst@example.com' }, {
    env: { HIBP_API_KEY: 'hibp-key' },
    fetchImpl: async (url, init) => {
      calls += 1;
      assert.equal(String(url), 'https://haveibeenpwned.com/api/v3/breachedaccount/analyst%40example.com?truncateResponse=false');
      const headers = new Headers(init.headers);
      assert.equal(headers.get('hibp-api-key'), 'hibp-key');
      assert.match(headers.get('user-agent') ?? '', /para11ax/i);
      return json([{
        Name: 'ExampleBreach',
        Title: 'Example Breach',
        Domain: 'breached.example',
        BreachDate: '2026-08-01',
        AddedDate: '2026-08-02T00:00:00Z',
        DataClasses: ['Email addresses', 'Passwords'],
      }]);
    },
  });
  assert.equal(calls, 1);
  assert.equal(output.observationType, 'identity_exposure');
  assert.equal(output.verdict, 'observed');
  assert.equal(output.confidence, null);
  assert.equal(output.attributes.breachCount, 1);
  assert.deepEqual(output.attributes.breaches[0].dataClasses, ['Email addresses', 'Passwords']);
  assertNoSecretSentinels(output);
});

test('HIBP verified-domain lookup aggregates aliases instead of retaining account identities', async () => {
  const output = await hibpProvider.run({ type: 'domain', value: 'example.com' }, {
    env: { HIBP_API_KEY: 'hibp-key' },
    fetchImpl: async (url, init) => {
      assert.equal(String(url), 'https://haveibeenpwned.com/api/v3/breacheddomain/example.com');
      assert.equal(new Headers(init.headers).get('hibp-api-key'), 'hibp-key');
      return json({
        alice: ['ExampleBreach', 'LegacyBreach'],
        security: ['ExampleBreach'],
      });
    },
  });
  assert.equal(output.verdict, 'observed');
  assert.equal(output.attributes.accountCount, 2);
  assert.deepEqual(output.attributes.breachNames, ['ExampleBreach', 'LegacyBreach']);
  assert.equal(JSON.stringify(output).includes('alice'), false);
  assert.equal(JSON.stringify(output).includes('security'), false);
});

test('HIBP 404 is no_result, never safe', async () => {
  const output = await hibpProvider.run({ type: 'email', value: 'nobody@example.com' }, {
    env: { HIBP_API_KEY: 'hibp-key' },
    fetchImpl: async () => json({ message: 'Not found' }, 404),
  });
  assert.equal(output.verdict, 'no_result');
  assert.equal(output.confidence, null);
});

test('Hudson Rock uses one filtered domain POST and discards credential material', async () => {
  let calls = 0;
  const output = await hudsonRockProvider.run({ type: 'domain', value: 'example.com' }, {
    env: { HUDSONROCK_API_KEY: 'hudson-key' },
    fetchImpl: async (url, init) => {
      calls += 1;
      assert.equal(String(url), 'https://api.hudsonrock.com/json/v3/search-by-domain');
      assert.equal(init.method, 'POST');
      const headers = new Headers(init.headers);
      assert.equal(headers.get('api-key'), 'hudson-key');
      assert.equal(headers.get('content-type'), 'application/json');
      assert.deepEqual(JSON.parse(init.body), { domains: ['example.com'], filter_credentials: true });
      return json({
        data: [{
          date_compromised: '2026-08-10T10:00:00Z',
          date_uploaded: '2026-08-11T10:00:00Z',
          credentials: [{
            domain: 'example.com',
            username: 'analyst@example.com',
            password: SECRET_SENTINELS[0],
            cookies: [SECRET_SENTINELS[1]],
          }],
          employee_session_cookies: [SECRET_SENTINELS[1]],
          access_token: SECRET_SENTINELS[2],
        }],
        nextCursor: 'opaque-sensitive-cursor',
      });
    },
  });
  assert.equal(calls, 1);
  assert.equal(output.observationType, 'identity_exposure');
  assert.equal(output.verdict, 'observed');
  assert.equal(output.attributes.recordCount, 1);
  assert.equal(output.attributes.truncated, true);
  assertNoSecretSentinels(output);
});

test('SpyCloud domain and email lookups retain only bounded exposure metadata', async () => {
  for (const input of [
    { type: 'domain', value: 'example.com', path: 'domains/example.com' },
    { type: 'email', value: 'analyst@example.com', path: 'emails/analyst%40example.com' },
  ]) {
    const output = await spyCloudProvider.run({ type: input.type, value: input.value }, {
      env: { SPYCLOUD_API_KEY: 'spycloud-key' },
      fetchImpl: async (url, init) => {
        assert.equal(String(url), `https://api.spycloud.io/enterprise-v2/breach/data/${input.path}`);
        assert.equal(new Headers(init.headers).get('x-api-key'), 'spycloud-key');
        return json({
          hits: 1,
          results: [{
            source_id: 42,
            severity: 5,
            spycloud_publish_date: '2026-08-12',
            email: 'analyst@example.com',
            password: SECRET_SENTINELS[0],
            cookie: SECRET_SENTINELS[1],
            session_token: SECRET_SENTINELS[2],
          }],
          cursor: 'opaque-sensitive-cursor',
        });
      },
    });
    assert.equal(output.observationType, 'identity_exposure');
    assert.equal(output.verdict, 'observed');
    assert.equal(output.confidence, null);
    assert.equal(output.attributes.recordCount, 1);
    assertNoSecretSentinels(output);
  }
});

test('sensitive exposure providers map empty results to no_result and reject malformed successes', async () => {
  const cases = [
    [hibpProvider, { type: 'email', value: 'nobody@example.com' }, { HIBP_API_KEY: 'key' }, []],
    [hudsonRockProvider, { type: 'domain', value: 'example.com' }, { HUDSONROCK_API_KEY: 'key' }, { data: [], nextCursor: null }],
    [spyCloudProvider, { type: 'domain', value: 'example.com' }, { SPYCLOUD_API_KEY: 'key' }, { hits: 0, results: [] }],
  ];
  for (const [provider, input, env, payload] of cases) {
    const output = await provider.run(input, { env, fetchImpl: async () => json(payload) });
    assert.equal(output.verdict, 'no_result', provider.name);
    assert.equal(output.confidence, null, provider.name);
  }

  await assert.rejects(
    hudsonRockProvider.run({ type: 'domain', value: 'example.com' }, {
      env: { HUDSONROCK_API_KEY: 'key' }, fetchImpl: async () => json({ data: 'not-an-array' }),
    }),
    /provider_schema_invalid/,
  );
  await assert.rejects(
    spyCloudProvider.run({ type: 'domain', value: 'example.com' }, {
      env: { SPYCLOUD_API_KEY: 'key' }, fetchImpl: async () => json({ results: 'not-an-array' }),
    }),
    /provider_schema_invalid/,
  );
});

test('sensitive exposure providers fail before egress when credentials are absent', async () => {
  for (const [provider, input] of [
    [hibpProvider, { type: 'email', value: 'analyst@example.com' }],
    [hudsonRockProvider, { type: 'domain', value: 'example.com' }],
    [spyCloudProvider, { type: 'domain', value: 'example.com' }],
  ]) {
    let called = false;
    await assert.rejects(provider.run(input, {
      env: {},
      fetchImpl: async () => { called = true; return json({}); },
    }), /not configured/i);
    assert.equal(called, false, provider.name);
  }
});
