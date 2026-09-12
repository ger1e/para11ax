import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

const read = path => readFileSync(path, 'utf8');

const assets = [
  ['assets/brand/para11ax-readme-hero-v9.svg', '720 360'],
  ['assets/brand/para11ax-readme-architecture-v6.svg', '720 780'],
  ['assets/brand/para11ax-readme-semantics-v5.svg', '720 860'],
  ['assets/brand/para11ax-readme-footer-v2.svg', '720 300'],
];

const entityMap = Object.freeze({
  '&amp;': '&',
  '&quot;': '"',
  '&#39;': "'",
  '&lt;': '<',
  '&gt;': '>',
});
const decodeEntitiesOnce = value => value.replace(/&(amp|quot|#39|lt|gt);/g, entity => entityMap[entity] ?? entity);

const visibleTextRows = svg => [...svg.matchAll(/<text\b([^>]*)>(.*?)<\/text>/gis)]
  .map(match => {
    const attrs = match[1];
    const body = decodeEntitiesOnce(match[2]
      .replace(/<tspan\b[^>]*>/gi, '')
      .replace(/<\/tspan>/gi, ''))
      .trim();
    const size = Number(attrs.match(/font-size=["']([\d.]+)["']/i)?.[1] ?? 0);
    return { body, size };
  })
  .filter(row => row.body && row.size >= 15);

test('README uses the normalized GER1E-style PARA11AX SVG family', () => {
  const readme = read('README.md');
  for (const [path] of assets) {
    assert.equal(existsSync(path), true, `${path} must exist`);
    assert.match(readme, new RegExp(path.replaceAll('/', '\\/').replaceAll('.', '\\.'), 'i'));
  }
  assert.doesNotMatch(readme, /para11ax-readme-hero-v8\.svg|para11ax-readme-architecture-v5\.svg|para11ax-readme-semantics-v4\.svg|para11ax-readme-footer-v1\.svg|para11ax-architecture-v3\.svg|para11ax-semantic-firewall-v3\.svg/i);
});

test('README SVGs preserve PARA11AX identity inside GER1E-normalized geometry', () => {
  for (const [path, viewBox] of assets) {
    const svg = read(path);
    assert.match(svg, new RegExp(`viewBox=["']0 0 ${viewBox}["']`, 'i'));
    assert.match(svg, /rx=["']12["']/i, `${path} must use GER1E-style rounded outer framing`);
    assert.match(svg, /ui-monospace|SFMono-Regular|Menlo|Consolas/i, `${path} must use the normalized mono stack`);
    assert.match(svg, /#020403/i, `${path} must preserve terminal black`);
    assert.match(svg, /#39FF14/i, `${path} must preserve phosphor green`);
    assert.match(svg, /#F7FFF6/i, `${path} must preserve signal white`);
    assert.doesNotMatch(svg, /#00E5FF|#F6C945|#39FF88/i, `${path} must not reintroduce legacy colors`);
  }
});

test('all active README SVG text rows stay inside the mobile-safe text budget', () => {
  for (const [path] of assets) {
    const rows = visibleTextRows(read(path));
    assert.ok(rows.length > 0, `${path} must expose visible text rows`);
    for (const row of rows) {
      if (row.size >= 90) continue;
      const limit = row.size >= 20 ? 46 : 52;
      assert.ok(row.body.length <= limit, `${path} has a mobile-risk text row (${row.body.length} > ${limit}): ${row.body}`);
    }
  }
});

test('semantic firewall detail rows stay inside the mobile-safe SVG text budget', () => {
  const svg = read('assets/brand/para11ax-readme-semantics-v5.svg');
  const rows = [...svg.matchAll(/<text[^>]*font-size=["']17["'][^>]*>([^<]*)<\/text>/gi)]
    .map(match => decodeEntitiesOnce(match[1]).trim());
  assert.ok(rows.length >= 8, 'semantic firewall must expose its detail rows as bounded text lines');
  for (const row of rows) {
    assert.ok(row.length <= 55, `semantic firewall detail row is too wide for mobile rendering: ${row}`);
  }
});

test('README adopts GER1E-style numbered information hierarchy without losing core contracts', () => {
  const readme = read('README.md');
  for (const section of [
    '01 // SYSTEM PROFILE',
    '02 // REQUEST PATH',
    '03 // ANALYST SURFACE',
    '04 // SEMANTIC FIREWALL',
    '05 // PROVIDER FABRIC',
    '06 // SECURITY & VERIFICATION',
    '07 // DEEP DOCS',
  ]) assert.match(readme, new RegExp(section.replace('/', '\\/'), 'i'));

  assert.match(readme, /Evidence v2/i);
  assert.match(readme, /Evidence Graph v1\.0/i);
  assert.match(readme, /Guidance v1\.0/i);
  assert.match(readme, /safeFetch/i);
  assert.match(readme, /39\s+(?:configured\s+)?sources/i);
  assert.match(readme, /OBSERVED ≠ INFERRED ≠ CONTEXTUAL/i);
  assert.match(readme, /No universal maliciousness score/i);
});
