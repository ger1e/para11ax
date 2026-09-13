import test from 'node:test';
import assert from 'node:assert/strict';
import { depsDevProvider } from '../src/providers/deps-dev.js';

function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
}

function context(fetchImpl) {
  return { signal: new AbortController().signal, fetchImpl };
}

test('deps.dev resolves an npm PURL into version metadata, advisories, and direct/transitive dependencies', async () => {
  const urls = [];
  const result = await depsDevProvider.run({ type: 'package', value: 'pkg:npm/react@18.2.0' }, context(async url => {
    const value = String(url);
    urls.push(value);
    if (value.endsWith('/versions/18.2.0')) return json({
      versionKey: { system: 'NPM', name: 'react', version: '18.2.0' },
      publishedAt: '2022-06-14T19:46:38Z',
      licenses: ['MIT'],
      advisoryKeys: [{ id: 'GHSA-test-1234' }],
      links: [{ label: 'SOURCE_REPO', url: 'https://github.com/facebook/react' }],
    });
    if (value.endsWith('/versions/18.2.0:dependencies')) return json({
      nodes: [
        { versionKey: { system: 'NPM', name: 'react', version: '18.2.0' }, relation: 'SELF' },
        { versionKey: { system: 'NPM', name: 'loose-envify', version: '1.4.0' }, relation: 'DIRECT' },
        { versionKey: { system: 'NPM', name: 'js-tokens', version: '4.0.0' }, relation: 'INDIRECT' },
      ],
      edges: [
        { fromNode: 0, toNode: 1, requirement: '^1.1.0' },
        { fromNode: 1, toNode: 2, requirement: '^3.0.0 || ^4.0.0' },
      ],
    });
    throw new Error(`unexpected URL: ${value}`);
  }));

  assert.deepEqual(urls, [
    'https://api.deps.dev/v3/systems/npm/packages/react/versions/18.2.0',
    'https://api.deps.dev/v3/systems/npm/packages/react/versions/18.2.0:dependencies',
  ]);
  assert.equal(result.observationType, 'supply_chain');
  assert.equal(result.verdict, 'resolved');
  assert.equal(result.attributes.purl, 'pkg:npm/react@18.2.0');
  assert.deepEqual(result.attributes.licenses, ['MIT']);
  assert.deepEqual(result.attributes.advisories, ['GHSA-test-1234']);
  assert.equal(result.attributes.directDependencyCount, 1);
  assert.equal(result.attributes.transitiveDependencyCount, 1);
  assert.deepEqual(result.relationships, [
    { targetType: 'advisory', target: 'GHSA-test-1234', relationship: 'affected_by' },
    { targetType: 'package', target: 'pkg:npm/loose-envify@1.4.0', relationship: 'direct_dependency', requirement: '^1.1.0' },
    { targetType: 'package', target: 'pkg:npm/js-tokens@4.0.0', relationship: 'transitive_dependency', requirement: '^3.0.0 || ^4.0.0' },
  ]);
});

test('deps.dev canonicalizes scoped npm and Maven package coordinates for API paths and relationship PURLs', async () => {
  const requests = [];
  const npm = await depsDevProvider.run({ type: 'package', value: 'pkg:npm/%40scope/name@1.2.3' }, context(async url => {
    requests.push(String(url));
    if (String(url).endsWith(':dependencies')) return json({ nodes: [{ versionKey: { system: 'NPM', name: '@scope/name', version: '1.2.3' }, relation: 'SELF' }], edges: [] });
    return json({ versionKey: { system: 'NPM', name: '@scope/name', version: '1.2.3' }, licenses: [], advisoryKeys: [] });
  }));
  assert.equal(npm.attributes.purl, 'pkg:npm/%40scope/name@1.2.3');
  assert.ok(requests[0].includes('/packages/%40scope%2Fname/versions/1.2.3'));

  requests.length = 0;
  const maven = await depsDevProvider.run({ type: 'package', value: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1' }, context(async url => {
    requests.push(String(url));
    if (String(url).endsWith(':dependencies')) return json({ nodes: [{ versionKey: { system: 'MAVEN', name: 'org.apache.logging.log4j:log4j-core', version: '2.17.1' }, relation: 'SELF' }], edges: [] });
    return json({ versionKey: { system: 'MAVEN', name: 'org.apache.logging.log4j:log4j-core', version: '2.17.1' }, licenses: ['Apache-2.0'], advisoryKeys: [] });
  }));
  assert.equal(maven.attributes.system, 'MAVEN');
  assert.ok(requests[0].includes('/systems/maven/packages/org.apache.logging.log4j%3Alog4j-core/versions/2.17.1'));
});

test('deps.dev treats missing package versions as no-result and does not claim supply-chain safety', async () => {
  let calls = 0;
  const result = await depsDevProvider.run({ type: 'package', value: 'pkg:npm/does-not-exist@1.0.0' }, context(async () => {
    calls += 1;
    return json({ code: 404 }, 404);
  }));
  assert.equal(calls, 1);
  assert.equal(result.verdict, 'no_result');
  assert.equal(result.attributes.resolved, false);
  assert.deepEqual(result.relationships, []);
});

test('deps.dev rejects malformed package identifiers and malformed graph schemas', async () => {
  await assert.rejects(
    depsDevProvider.run({ type: 'package', value: 'pkg:npm/react' }, context(async () => json({}))),
    /invalid package PURL/,
  );
  await assert.rejects(
    depsDevProvider.run({ type: 'domain', value: 'example.com' }, context(async () => json({}))),
    /unsupported deps.dev input/,
  );
  await assert.rejects(
    depsDevProvider.run({ type: 'package', value: 'pkg:npm/react@18.2.0' }, context(async url => {
      if (String(url).endsWith(':dependencies')) return json({ nodes: {}, edges: [] });
      return json({ versionKey: { system: 'NPM', name: 'react', version: '18.2.0' }, licenses: [], advisoryKeys: [] });
    })),
    /invalid deps.dev dependency graph/,
  );
});

test('deps.dev hard-caps emitted graph relationships', async () => {
  const nodes = [{ versionKey: { system: 'NPM', name: 'root', version: '1.0.0' }, relation: 'SELF' }];
  const edges = [];
  for (let index = 1; index <= 150; index += 1) {
    nodes.push({ versionKey: { system: 'NPM', name: `dep-${index}`, version: '1.0.0' }, relation: index <= 20 ? 'DIRECT' : 'INDIRECT' });
    edges.push({ fromNode: index === 1 ? 0 : index - 1, toNode: index, requirement: '^1.0.0' });
  }
  const result = await depsDevProvider.run({ type: 'package', value: 'pkg:npm/root@1.0.0' }, context(async url => {
    if (String(url).endsWith(':dependencies')) return json({ nodes, edges });
    return json({ versionKey: { system: 'NPM', name: 'root', version: '1.0.0' }, licenses: [], advisoryKeys: [] });
  }));
  assert.ok(result.relationships.length <= 100);
  assert.equal(result.attributes.relationshipsTruncated, true);
});
