import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { PARA11AX_BOOT_LINES } from '../app/boot.js';

const read = path => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const manifest = JSON.parse(read('config/providers.json'));
const upstreamSourceCount = new Set(
  Object.entries(manifest).map(([name, policy]) => policy.providerFamily ?? name),
).size;

test('boot reports the executable upstream source-family count', () => {
  const providerLine = PARA11AX_BOOT_LINES.find(line => line.includes('provider-registry]:'));
  assert.equal(
    providerLine,
    `[    0.489668] pxsvc[provider-registry]: ${upstreamSourceCount} sources registered [ OK ]`,
  );
});

test('final brand normalization replaces legacy footer counts with source truth', async () => {
  const previousDocument = globalThis.document;
  const previousMutationObserver = globalThis.MutationObserver;
  const nodes = [
    { textContent: '37 SOURCES · EVIDENCE v2 · READ ONLY' },
    { textContent: '38 SRC · READ ONLY' },
  ];
  globalThis.document = {
    getElementById: () => null,
    querySelectorAll: () => nodes,
  };
  globalThis.MutationObserver = undefined;

  try {
    await import(`../app/brand-final.js?source-parity=${Date.now()}`);
  } finally {
    if (previousDocument === undefined) delete globalThis.document;
    else globalThis.document = previousDocument;
    if (previousMutationObserver === undefined) delete globalThis.MutationObserver;
    else globalThis.MutationObserver = previousMutationObserver;
  }

  assert.deepEqual(nodes.map(node => node.textContent), [
    `${upstreamSourceCount} SOURCES · EVIDENCE v2 · READ ONLY`,
    `${upstreamSourceCount} SRC · READ ONLY`,
  ]);
});

test('tracked architecture artwork reports the executable upstream source-family count', () => {
  const paths = execFileSync('git', ['ls-files', 'assets/brand/*architecture*.svg'], { encoding: 'utf8' })
    .trim()
    .split('\n')
    .filter(Boolean)
    .filter(path => /FIXED SOURCES/i.test(read(path)));

  assert.ok(paths.length > 0, 'expected tracked architecture artwork with a source-count label');
  for (const path of paths) {
    assert.match(read(path), new RegExp(`\\b${upstreamSourceCount} FIXED SOURCES\\b`, 'i'), `${path} source-count drift`);
  }
});
