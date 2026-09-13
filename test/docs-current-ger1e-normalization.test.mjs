import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';

const read = path => readFileSync(path, 'utf8');

const DOC_STANDARD_MARKER = '<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->';
const DOC_STANDARD_FOOTER = /PΛRΛ11ΛX\s*\/\/\s*PER ASPERA AD ASTRA/i;
const ALL_MARKDOWN_DOCS = execFileSync('git', ['ls-files', '*.md'], { encoding: 'utf8' })
  .trim()
  .split('\n')
  .filter(Boolean)
  .sort();
const HISTORICAL_DOCS = ALL_MARKDOWN_DOCS.filter(path => path.startsWith('docs/superpowers/'));

const PUBLIC_DOCS = [
  'README.md',
  'SECURITY.md',
  'CONTRIBUTING.md',
  'CHANGELOG.md',
  'docs/API.md',
  'docs/ARCHITECTURE.md',
  'docs/BRAND.md',
  'docs/END-TO-END-EXAMPLE.md',
  'docs/EVIDENCE-SCHEMA.md',
  'docs/OPERATIONS.md',
  'docs/PROVIDERS.md',
  'docs/PUBLIC-RELEASE-CHECKLIST.md',
  'docs/QA-REPORT.md',
  'docs/SECURITY-CONTROLS.md',
  'docs/SHODAN-SHELL.md',
  'docs/THREAT-MODEL.md',
];

test('README SVG family matches GER1E width and typography scale', () => {
  const heroPath = 'assets/brand/para11ax-readme-hero-v9.svg';
  const architecturePath = 'assets/brand/para11ax-readme-architecture-v6.svg';
  const semanticsPath = 'assets/brand/para11ax-readme-semantics-v5.svg';
  const footerPath = 'assets/brand/para11ax-readme-footer-v2.svg';
  for (const path of [heroPath, architecturePath, semanticsPath, footerPath]) {
    assert.equal(existsSync(path), true, `${path} must exist`);
  }

  const hero = read(heroPath);
  assert.match(hero, /viewBox=["']0 0 720 360["']/i);
  assert.match(hero, /\.r\{[^}]*font-size:13px/is, 'hero primary rain must match GER1E 13px');
  assert.match(hero, /\.r2\{[^}]*font-size:12px/is, 'hero secondary rain must match GER1E 12px');
  assert.match(hero, /font-size=["']102["'][^>]*>PΛRΛ/i, 'PARA11AX primary mark must match GER1E 102px hero scale');
  assert.match(hero, /font-size=["']22["'][^>]*>CTI ENRICHMENT/i);
  assert.match(hero, /font-size=["']17["'][^>]*>EVIDENCE V2/i);
  assert.match(hero, /font-size=["']17["'][^>]*>“You’ve got to follow the evidence/i);
  assert.match(hero, /font-size=["']15["'][^>]*>— JOHN KIRIAKOU/i);

  for (const path of [architecturePath, semanticsPath]) {
    const svg = read(path);
    assert.match(svg, /viewBox=["']0 0 720 /i);
    assert.match(svg, /font-size=["']15["']/i, `${path} must retain GER1E microtype scale`);
    assert.match(svg, /font-size=["']22["']/i, `${path} must retain GER1E heading scale`);
    assert.match(svg, /font-size=["']17["']/i, `${path} must use GER1E body scale`);
    assert.doesNotMatch(svg, /font-size=["']16["']/i, `${path} must not retain the old 16px PARA11AX body scale`);
  }

  const footer = read(footerPath);
  assert.match(footer, /viewBox=["']0 0 720 300["']/i);
  assert.match(footer, /font-size=["']15["']/i);
  assert.match(footer, /font-size=["']17["']/i);
  assert.match(footer, /font-size=["']22["']/i);
  assert.match(footer, /PER ASPERA AD ASTRA/i);

  const readme = read('README.md');
  assert.match(readme, /para11ax-readme-footer-v2\.svg/i);
  assert.doesNotMatch(readme, /para11ax-radar-lockup\.svg[^\n]*width=["']320["']/i);
});

test('README describes the merged scheduler and Intelligence Kernel reference architecture', () => {
  const readme = read('README.md');
  assert.match(readme, /Provider Value Scheduler v1\.0/i);
  assert.match(readme, /Intelligence Kernel v1\.0/i);
  assert.match(readme, /24-provider IP workflow/i);
  assert.match(readme, /48-call ceiling/i);
  assert.match(readme, /evidence strength/i);
  assert.match(readme, /analyst priority/i);
  assert.match(readme, /coverage impact/i);
  assert.match(readme, /one-hop pivots/i);
  assert.match(readme, /no LLM/i);
  assert.match(readme, /derived context/i);
});

test('canonical deep docs describe scheduler v1, Kernel v1, and evidence boundaries', () => {
  const architecture = read('docs/ARCHITECTURE.md');
  assert.match(architecture, /Provider Value Scheduler v1\.0/i);
  assert.match(architecture, /Intelligence Kernel v1\.0/i);
  assert.match(architecture, /24-provider IP workflow/i);
  assert.match(architecture, /48-call ceiling/i);
  assert.doesNotMatch(architecture, /tiered scheduler/i);

  const evidence = read('docs/EVIDENCE-SCHEMA.md');
  assert.match(evidence, /Intelligence Kernel v1\.0/i);
  assert.match(evidence, /derived context/i);
  assert.match(evidence, /does not become Evidence v2|not Evidence v2/i);

  const providers = read('docs/PROVIDERS.md');
  assert.match(providers, /Provider Value Scheduler v1\.0/i);
  assert.match(providers, /24-provider IP workflow/i);
  assert.match(providers, /48-call ceiling/i);

  const api = read('docs/API.md');
  assert.match(api, /intelligence/i);
  assert.match(api, /Intelligence Kernel v1\.0/i);

  const operations = read('docs/OPERATIONS.md');
  assert.match(operations, /11d7b861d9f626c45f44c138c8d72cee9493efdf/i);
  assert.match(operations, /build-rate limit|deployment rate limit/i);

  const qa = read('docs/QA-REPORT.md');
  assert.match(qa, /11d7b861d9f626c45f44c138c8d72cee9493efdf/i);
  assert.match(qa, /Tooling smoke 1374/i);
  assert.match(qa, /CodeQL 962/i);
  assert.match(qa, /2acc19f0558b1c3bbbcd96b47b8da69a25192c55/i);
});

test('all current public docs are free of stale scheduler/provider-count language', () => {
  for (const path of PUBLIC_DOCS) {
    const content = read(path);
    assert.doesNotMatch(content, /tiered scheduler/i, `${path} still documents the retired tiered scheduler`);
    assert.doesNotMatch(content, /37\s+(?:configured\s+)?(?:providers|sources)|37\s+FIXED\s+SOURCES/i, `${path} still documents the retired 37-source count`);
  }
});

test('security and contribution docs preserve deterministic no-LLM and no-new-egress boundaries', () => {
  for (const path of ['SECURITY.md', 'docs/SECURITY-CONTROLS.md', 'docs/THREAT-MODEL.md']) {
    const content = read(path);
    assert.match(content, /Intelligence Kernel v1\.0/i, `${path} must document Kernel v1`);
    assert.match(content, /no new egress|does not add egress|adds no egress/i, `${path} must state the kernel/scheduler egress boundary`);
    assert.match(content, /no LLM|LLM-free|without LLM/i, `${path} must state the no-LLM boundary`);
  }
  const contributing = read('CONTRIBUTING.md');
  assert.match(contributing, /Provider Value Scheduler v1\.0/i);
  assert.match(contributing, /Intelligence Kernel v1\.0/i);
  assert.match(contributing, /Evidence v2 remains authoritative/i);
});

test('every tracked Markdown document uses the GER1E/PARA11AX document standard', () => {
  assert.ok(ALL_MARKDOWN_DOCS.length > PUBLIC_DOCS.length, 'repository-wide contract must cover more than canonical public docs');
  for (const path of ALL_MARKDOWN_DOCS) {
    const content = read(path);
    assert.ok(content.startsWith(`${DOC_STANDARD_MARKER}\n`), `${path} must start with the shared document-standard marker`);
    assert.match(content, DOC_STANDARD_FOOTER, `${path} must carry the shared PARA11AX footer`);
  }
});

test('historical Superpowers plans/specs are standardized without pretending to be current architecture', () => {
  assert.ok(HISTORICAL_DOCS.length > 0, 'historical Superpowers archive must be present');
  for (const path of HISTORICAL_DOCS) {
    const content = read(path);
    assert.match(content, /Historical design record/i, `${path} must be clearly labeled historical`);
    assert.match(content, /docs\/ARCHITECTURE\.md|ARCHITECTURE\.md/i, `${path} must point readers to the current architecture`);
  }
});

test('supporting Markdown surfaces are explicitly covered by the same standard', () => {
  for (const path of [
    '.github/pull_request_template.md',
    'maltego/README.md',
    'maltego/README-compatibility.md',
    'workers/user-scanner/README.md',
  ]) {
    assert.ok(ALL_MARKDOWN_DOCS.includes(path), `${path} must be tracked by the repository-wide documentation contract`);
    const content = read(path);
    assert.ok(content.startsWith(`${DOC_STANDARD_MARKER}\n`), `${path} must use the shared marker`);
    assert.match(content, DOC_STANDARD_FOOTER, `${path} must use the shared footer`);
  }
});
