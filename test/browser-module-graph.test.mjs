import assert from 'node:assert/strict';
import { access, readFile } from 'node:fs/promises';
import { extname, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';

const repoRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
const browserEntry = pathToFileURL(resolve(repoRoot, 'app/terminal-main.js'));

function moduleSpecifiers(source) {
  const specifiers = new Set();
  const patterns = [
    /(?:^|\n)\s*import\s+(?:[^'\"]*?\s+from\s+)?['\"]([^'\"]+)['\"]/g,
    /(?:^|\n)\s*export\s+(?:\*|\{[^}]*\})\s+from\s+['\"]([^'\"]+)['\"]/g,
    /\bimport\s*\(\s*['\"]([^'\"]+)['\"]\s*\)/g,
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) specifiers.add(match[1]);
  }
  return [...specifiers];
}

async function browserModuleGraph(entry) {
  const queue = [{ url: entry, chain: [relative(repoRoot, fileURLToPath(entry))] }];
  const visited = new Set();
  const modules = new Map();
  const violations = [];

  while (queue.length) {
    const current = queue.shift();
    if (visited.has(current.url.href)) continue;
    visited.add(current.url.href);

    const source = await readFile(current.url, 'utf8');
    modules.set(current.url.href, {
      path: relative(repoRoot, fileURLToPath(current.url)),
      source,
    });
    for (const specifier of moduleSpecifiers(source)) {
      if (specifier.startsWith('node:') || (!specifier.startsWith('.') && !specifier.startsWith('/'))) {
        violations.push([...current.chain, specifier].join(' -> '));
        continue;
      }

      const resolvedUrl = new URL(specifier, current.url);
      const resolvedPath = fileURLToPath(resolvedUrl);
      const displayPath = relative(repoRoot, resolvedPath);
      if (displayPath.startsWith('..')) {
        violations.push([...current.chain, specifier].join(' -> '));
        continue;
      }
      try {
        await access(resolvedPath);
      } catch {
        violations.push([...current.chain, `${displayPath} (missing)`].join(' -> '));
        continue;
      }
      if (['.js', '.mjs'].includes(extname(resolvedPath))) {
        queue.push({ url: resolvedUrl, chain: [...current.chain, displayPath] });
      }
    }
  }

  return { modules, violations: violations.sort() };
}

test('desktop boot entry resolves only browser-loadable local modules', async () => {
  const graph = await browserModuleGraph(browserEntry);
  assert.deepEqual(graph.violations, []);
});

test('desktop browser modules do not rely on Node-only globals', async () => {
  const graph = await browserModuleGraph(browserEntry);
  const patterns = [
    ['process', /\bprocess(?:\.|\s*\[)/],
    ['require', /\brequire\s*\(/],
    ['Node path globals', /\b__(?:dirname|filename)\b/],
  ];
  const violations = [];
  for (const module of graph.modules.values()) {
    if (/\bBuffer(?:\.|\s*\()/.test(module.source) && !/typeof\s+Buffer/.test(module.source)) {
      violations.push(`${module.path} -> Buffer`);
    }
    for (const [name, pattern] of patterns) {
      if (pattern.test(module.source)) violations.push(`${module.path} -> ${name}`);
    }
  }
  assert.deepEqual(violations.sort(), []);
});
