import test from 'node:test';
import assert from 'node:assert/strict';
import { depsDevProvider } from '../src/providers/deps-dev.js';

function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
}

function version(overrides = {}) {
  return {
    versionKey: { system: 'NPM', name: 'react', version: '18.2.0' },
    publishedAt: '2022-06-14T19:46:42Z',
    isDefault: false,
    isDeprecated: false,
    deprecatedReason: '',
    licenses: ['MIT'],
    advisoryKeys: [{ id: 'GHSA-test' }],
    links: [],
    ...overrides,
  };
}

function graph(overrides = {}) {
  return {
    nodes: [
      { versionKey: { system: 'NPM', name: 'react', version: '18.2.0' }, bundled: false, relation: 'SELF', errors: [] },
      { versionKey: { system: 'NPM', name: 'loose-envify', version: '1.4.0' }, bundled: false, relation: 'DIRECT', errors: [] },
      { versionKey: { system: 'NPM', name: 'js-tokens', version: '4.0.0' }, bundled: false, relation: 'INDIRECT', errors: [] },
    ],
    edges: [
      { fromNode: 0, toNode: 1, requirement: '^1.1.0' },
      { fromNode: 1, toNode: 2, requirement: '^3.0.0 || ^4.0.0' },
    ],
    error: '',
    ...overrides,
  };
}

function context(fetchImpl) {
  return { signal: new AbortController().signal, fetchImpl };
}

test('deps.dev is a bounded package supply-chain provider', () => {
  assert.equal(depsDevProvider.name, 'deps-dev');
  assert.deepEqual(depsDevProvider.types, ['package']);
  assert.equal(depsDevProvider.observationType, 'supply_chain');
});

test('deps.dev resolves one fixed version and dependency graph and preserves direct versus transitive relations', async () => {
  const calls = [];
  const result = await depsDevProvider.run({ type: 'package', value: 'pkg:npm/react@18.2.0' }, context(async url => {
    const value = String(url);
    calls.push(value);
    if (value.endsWith('/versions/18.2.0')) return json(version());
    if (value.endsWith('/versions/18.2.0:dependencies')) return json(graph());
    return json({ error: 'unexpected' }, 500);
  }));

  assert.deepEqual(calls, [
    'https://api.deps.dev/v3/systems/npm/packages/react/versions/18.2.0',
    'https://api.deps.dev/v3/systems/npm/packages/react/versions/18.2.0:dependencies',
  ]);
  assert.equal(result.observationType, 'supply_chain');
  assert.equal(result.verdict, 'observed');
  assert.equal(result.confidence, 100);
  assert.equal(result.attributes.purl, 'pkg:npm/react@18.2.0');
  assert.equal(result.attributes.system, 'NPM');
  assert.equal(result.attributes.name, 'react');
  assert.equal(result.attributes.version, '18.2.0');
  assert.equal(result.attributes.publishedAt, '2022-06-14T19:46:42Z');
  assert.deepEqual(result.attributes.licenses, ['MIT']);
  assert.deepEqual(result.attributes.advisories, ['GHSA-test']);
  assert.equal(result.attributes.directDependencyCount, 1);
  assert.equal(result.attributes.transitiveDependencyCount, 1);
  assert.equal(result.attributes.dependencyCount, 2);
  assert.deepEqual(result.relationships, [
    { targetType: 'package', target: 'pkg:npm/loose-envify@1.4.0', relationship: 'direct_dependency' },
    { targetType: 'package', target: 'pkg:npm/js-tokens@4.0.0', relationship: 'transitive_dependency' },
  ]);
  assert.deepEqual(result.references, calls);
});

test('deps.dev treats an unknown package version as neutral absence without requesting its dependency graph', async () => {
  const calls = [];
  const result = await depsDevProvider.run({ type: 'package', value: 'pkg:npm/does-not-exist-para11ax@0.0.0' }, context(async url => {
    calls.push(String(url));
    return json({ code: 404, message: 'not found' }, 404);
  }));

  assert.equal(calls.length, 1);
  assert.equal(result.observationType, 'supply_chain');
  assert.equal(result.verdict, 'no_result');
  assert.equal(result.confidence, 100);
  assert.deepEqual(result.relationships, []);
  assert.deepEqual(result.attributes, {
    purl: 'pkg:npm/does-not-exist-para11ax@0.0.0',
    system: 'NPM',
    name: 'does-not-exist-para11ax',
    version: '0.0.0',
    publishedAt: null,
    licenses: [],
    advisories: [],
    directDependencyCount: 0,
    transitiveDependencyCount: 0,
    dependencyCount: 0,
  });
});

test('deps.dev rejects malformed or unsupported PURLs before network access', async () => {
  let calls = 0;
  const fetchImpl = async () => { calls += 1; return json({}); };
  for (const value of [
    'pkg:npm/react',
    'pkg:npm/react@',
    'pkg:golang/example.com/mod@v1.0.0',
    'pkg:npm/react@18.2.0?arch=x64',
    'pkg:npm/react@18.2.0#src',
  ]) {
    await assert.rejects(
      depsDevProvider.run({ type: 'package', value }, context(fetchImpl)),
      /unsupported deps.dev package input/,
    );
  }
  assert.equal(calls, 0);
});

test('deps.dev fails closed on upstream schema drift and graph errors', async () => {
  await assert.rejects(
    depsDevProvider.run({ type: 'package', value: 'pkg:npm/react@18.2.0' }, context(async url => {
      if (String(url).endsWith('/versions/18.2.0')) return json(version({ licenses: 'MIT' }));
      return json(graph());
    })),
    /provider_schema_invalid/,
  );

  await assert.rejects(
    depsDevProvider.run({ type: 'package', value: 'pkg:npm/react@18.2.0' }, context(async url => {
      if (String(url).endsWith('/versions/18.2.0')) return json(version());
      return json(graph({ error: 'resolution incomplete' }));
    })),
    /provider_graph_incomplete/,
  );
});

test('deps.dev rejects runaway dependency graphs at the hard node bound', async () => {
  const nodes = [
    { versionKey: { system: 'NPM', name: 'react', version: '18.2.0' }, bundled: false, relation: 'SELF', errors: [] },
  ];
  for (let i = 0; i < 101; i += 1) {
    nodes.push({
      versionKey: { system: 'NPM', name: `dep-${i}`, version: '1.0.0' },
      bundled: false,
      relation: i === 0 ? 'DIRECT' : 'INDIRECT',
      errors: [],
    });
  }

  await assert.rejects(
    depsDevProvider.run({ type: 'package', value: 'pkg:npm/react@18.2.0' }, context(async url => {
      if (String(url).endsWith('/versions/18.2.0')) return json(version());
      return json(graph({ nodes, edges: [] }));
    })),
    /provider_graph_limit/,
  );
});
