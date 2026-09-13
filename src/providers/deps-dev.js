import { fetchJson } from '../core/fetch-json.js';
import { relation } from './helpers.js';

const API_BASE = 'https://api.deps.dev/v3';
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const MAX_RELATIONSHIPS = 100;
const MAX_ADVISORIES = 64;
const MAX_NODES = 2000;
const MAX_EDGES = 4000;

const SYSTEMS = Object.freeze({
  npm: Object.freeze({ api: 'npm', key: 'NPM', dependencies: true }),
  cargo: Object.freeze({ api: 'cargo', key: 'CARGO', dependencies: true }),
  maven: Object.freeze({ api: 'maven', key: 'MAVEN', dependencies: true }),
  pypi: Object.freeze({ api: 'pypi', key: 'PYPI', dependencies: true }),
  golang: Object.freeze({ api: 'go', key: 'GO', dependencies: false }),
  gem: Object.freeze({ api: 'rubygems', key: 'RUBYGEMS', dependencies: false }),
  nuget: Object.freeze({ api: 'nuget', key: 'NUGET', dependencies: false }),
});

function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function decode(value) {
  try { return decodeURIComponent(value); } catch { throw new Error('invalid package PURL'); }
}

function encodePurlSegment(value) {
  return encodeURIComponent(value).replace(/%2F/gi, '/');
}

function parsePurl(value) {
  if (typeof value !== 'string' || value.length > 4096 || !value.startsWith('pkg:') || value.includes('?') || value.includes('#')) {
    throw new Error('invalid package PURL');
  }
  const slash = value.indexOf('/');
  if (slash < 5) throw new Error('invalid package PURL');
  const type = value.slice(4, slash).toLowerCase();
  const policy = SYSTEMS[type];
  if (!policy) throw new Error('invalid package PURL');
  const coordinate = value.slice(slash + 1);
  const versionAt = coordinate.lastIndexOf('@');
  if (versionAt <= 0 || versionAt === coordinate.length - 1) throw new Error('invalid package PURL');
  const encodedName = coordinate.slice(0, versionAt);
  const encodedVersion = coordinate.slice(versionAt + 1);
  const decodedName = decode(encodedName);
  const version = decode(encodedVersion);
  if (!decodedName || !version || /[\u0000-\u001f\u007f\s]/.test(version)) throw new Error('invalid package PURL');

  let apiName = decodedName;
  if (type === 'maven') {
    const parts = decodedName.split('/').filter(Boolean);
    if (parts.length < 2) throw new Error('invalid package PURL');
    apiName = `${parts.slice(0, -1).join('.')}:${parts.at(-1)}`;
  }
  return Object.freeze({ type, ...policy, name: decodedName, apiName, version, purl: value });
}

function purlFromVersionKey(versionKey) {
  if (!plain(versionKey) || typeof versionKey.system !== 'string' || typeof versionKey.name !== 'string' || typeof versionKey.version !== 'string') return null;
  const system = versionKey.system.toUpperCase();
  const version = encodePurlSegment(versionKey.version);
  if (!version) return null;
  if (system === 'NPM') return `pkg:npm/${encodePurlSegment(versionKey.name)}@${version}`;
  if (system === 'CARGO') return `pkg:cargo/${encodePurlSegment(versionKey.name)}@${version}`;
  if (system === 'PYPI') return `pkg:pypi/${encodePurlSegment(versionKey.name)}@${version}`;
  if (system === 'NUGET') return `pkg:nuget/${encodePurlSegment(versionKey.name)}@${version}`;
  if (system === 'RUBYGEMS') return `pkg:gem/${encodePurlSegment(versionKey.name)}@${version}`;
  if (system === 'GO') return `pkg:golang/${encodePurlSegment(versionKey.name)}@${version}`;
  if (system === 'MAVEN') {
    const split = versionKey.name.lastIndexOf(':');
    if (split <= 0 || split === versionKey.name.length - 1) return null;
    const namespace = versionKey.name.slice(0, split).replace(/:/g, '.');
    const artifact = versionKey.name.slice(split + 1);
    return `pkg:maven/${encodePurlSegment(namespace)}/${encodePurlSegment(artifact)}@${version}`;
  }
  return null;
}

function versionUrl(pkg) {
  return `${API_BASE}/systems/${encodeURIComponent(pkg.api)}/packages/${encodeURIComponent(pkg.apiName)}/versions/${encodeURIComponent(pkg.version)}`;
}

function validateVersion(raw, pkg) {
  if (!plain(raw) || !plain(raw.versionKey)) throw new Error('invalid deps.dev version response');
  const key = raw.versionKey;
  if (String(key.system ?? '').toUpperCase() !== pkg.key || key.name !== pkg.apiName || key.version !== pkg.version) {
    throw new Error('invalid deps.dev version response');
  }
  if (raw.licenses !== undefined && !Array.isArray(raw.licenses)) throw new Error('invalid deps.dev version response');
  if (raw.advisoryKeys !== undefined && !Array.isArray(raw.advisoryKeys)) throw new Error('invalid deps.dev version response');
}

function advisories(raw) {
  return [...new Set((Array.isArray(raw.advisoryKeys) ? raw.advisoryKeys : [])
    .map(item => plain(item) && typeof item.id === 'string' ? item.id.trim() : '')
    .filter(Boolean))].sort().slice(0, MAX_ADVISORIES);
}

function licenses(raw) {
  return [...new Set((Array.isArray(raw.licenses) ? raw.licenses : [])
    .filter(item => typeof item === 'string' && item.trim())
    .map(item => item.trim()))].sort().slice(0, 64);
}

function validateGraph(raw) {
  if (!plain(raw) || !Array.isArray(raw.nodes) || !Array.isArray(raw.edges) || raw.nodes.length > MAX_NODES || raw.edges.length > MAX_EDGES) {
    throw new Error('invalid deps.dev dependency graph');
  }
  for (const node of raw.nodes) {
    if (!plain(node) || !plain(node.versionKey) || !['SELF', 'DIRECT', 'INDIRECT'].includes(String(node.relation ?? '').toUpperCase())) {
      throw new Error('invalid deps.dev dependency graph');
    }
    if (!purlFromVersionKey(node.versionKey)) throw new Error('invalid deps.dev dependency graph');
  }
  for (const edge of raw.edges) {
    if (!plain(edge) || !Number.isSafeInteger(edge.fromNode) || !Number.isSafeInteger(edge.toNode)
      || edge.fromNode < 0 || edge.toNode < 0 || edge.fromNode >= raw.nodes.length || edge.toNode >= raw.nodes.length) {
      throw new Error('invalid deps.dev dependency graph');
    }
    if (edge.requirement !== undefined && typeof edge.requirement !== 'string') throw new Error('invalid deps.dev dependency graph');
  }
}

function graphRelations(raw) {
  validateGraph(raw);
  const firstRequirement = new Map();
  for (const edge of raw.edges) {
    if (!firstRequirement.has(edge.toNode) && typeof edge.requirement === 'string' && edge.requirement.trim()) {
      firstRequirement.set(edge.toNode, edge.requirement.trim());
    }
  }
  const output = [];
  let directDependencyCount = 0;
  let transitiveDependencyCount = 0;
  for (let index = 0; index < raw.nodes.length; index += 1) {
    const node = raw.nodes[index];
    const depth = String(node.relation).toUpperCase();
    if (depth === 'SELF') continue;
    if (depth === 'DIRECT') directDependencyCount += 1;
    if (depth === 'INDIRECT') transitiveDependencyCount += 1;
    const purl = purlFromVersionKey(node.versionKey);
    const requirement = firstRequirement.get(index);
    output.push(relation('package', purl, depth === 'DIRECT' ? 'direct_dependency' : 'transitive_dependency', requirement ? { requirement } : {}));
  }
  return { output, directDependencyCount, transitiveDependencyCount };
}

function noResult(pkg, reference) {
  return {
    observationType: 'supply_chain',
    verdict: 'no_result',
    attributes: {
      purl: pkg.purl,
      system: pkg.key,
      resolved: false,
      licenses: [],
      advisories: [],
      directDependencyCount: 0,
      transitiveDependencyCount: 0,
      relationshipsTruncated: false,
    },
    relationships: [],
    references: [reference],
  };
}

export const depsDevProvider = Object.freeze({
  name: 'deps-dev',
  types: ['package'],
  cacheTtlMs: 24 * 60 * 60 * 1000,
  negativeCacheTtlMs: 6 * 60 * 60 * 1000,
  costClass: 'free',
  timeoutMs: 7000,
  parserVersion: 'v3-2026-09-13.1',
  async run(input, context = {}) {
    if (input?.type !== 'package' || typeof input.value !== 'string') throw new Error('unsupported deps.dev input');
    const pkg = parsePurl(input.value);
    const baseUrl = versionUrl(pkg);
    let version;
    try {
      version = await fetchJson(baseUrl, { fetchImpl: context.fetchImpl, signal: context.signal, maxBytes: MAX_RESPONSE_BYTES });
    } catch (error) {
      if (error?.status === 404) return noResult(pkg, baseUrl);
      throw error;
    }
    validateVersion(version, pkg);

    const advisoryIds = advisories(version);
    const relationships = advisoryIds.map(id => relation('advisory', id, 'affected_by'));
    let directDependencyCount = 0;
    let transitiveDependencyCount = 0;

    if (pkg.dependencies) {
      const graph = await fetchJson(`${baseUrl}:dependencies`, {
        fetchImpl: context.fetchImpl,
        signal: context.signal,
        maxBytes: MAX_RESPONSE_BYTES,
      });
      const projected = graphRelations(graph);
      directDependencyCount = projected.directDependencyCount;
      transitiveDependencyCount = projected.transitiveDependencyCount;
      relationships.push(...projected.output);
    }

    const truncated = relationships.length > MAX_RELATIONSHIPS;
    return {
      observationType: 'supply_chain',
      verdict: 'resolved',
      firstSeen: typeof version.publishedAt === 'string' ? version.publishedAt : null,
      attributes: {
        purl: pkg.purl,
        system: pkg.key,
        resolved: true,
        licenses: licenses(version),
        advisories: advisoryIds,
        directDependencyCount,
        transitiveDependencyCount,
        relationshipsTruncated: truncated,
      },
      relationships: relationships.slice(0, MAX_RELATIONSHIPS),
      references: [baseUrl],
    };
  },
});
