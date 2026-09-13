import { fetchJson } from '../core/fetch-json.js';

const API_BASE = 'https://api.deps.dev/v3';
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_DEPENDENCIES = 100;
const MAX_EDGES = 300;
const SUPPORTED_SYSTEMS = Object.freeze(new Map([
  ['npm', 'NPM'],
  ['cargo', 'CARGO'],
  ['maven', 'MAVEN'],
  ['pypi', 'PYPI'],
]));

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function inputError() {
  return new Error('unsupported deps.dev package input');
}

function schemaError() {
  return new Error('provider_schema_invalid');
}

function graphIncomplete() {
  return new Error('provider_graph_incomplete');
}

function graphLimit() {
  return new Error('provider_graph_limit');
}

function decodePart(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    throw inputError();
  }
}

function validText(value, max = 512) {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= max
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function packageNameFromPurl(system, rawName) {
  const segments = rawName.split('/');
  if (segments.some(part => !part)) throw inputError();

  if (system === 'NPM') {
    if (segments.length === 1) {
      const name = decodePart(segments[0]);
      if (!validText(name, 214) || name.startsWith('@') || /[\s/]/.test(name)) throw inputError();
      return name;
    }
    if (segments.length === 2) {
      const scope = decodePart(segments[0]);
      const name = decodePart(segments[1]);
      if (!validText(scope, 214) || !validText(name, 214) || !scope.startsWith('@') || /[\s/]/.test(scope) || /[\s/]/.test(name)) throw inputError();
      return `${scope}/${name}`;
    }
    throw inputError();
  }

  if (system === 'MAVEN') {
    if (segments.length !== 2) throw inputError();
    const group = decodePart(segments[0]);
    const artifact = decodePart(segments[1]);
    if (!validText(group, 255) || !validText(artifact, 255) || /[\s/:]/.test(group) || /[\s/:]/.test(artifact)) throw inputError();
    return `${group}:${artifact}`;
  }

  if (segments.length !== 1) throw inputError();
  const name = decodePart(segments[0]);
  if (!validText(name, 255) || /[\s/]/.test(name)) throw inputError();
  return name;
}

function parsePurl(value) {
  if (typeof value !== 'string' || value.length < 10 || value.length > 1024 || !value.startsWith('pkg:')) throw inputError();
  if (value.includes('?') || value.includes('#')) throw inputError();

  const slash = value.indexOf('/', 4);
  if (slash <= 4) throw inputError();
  const type = value.slice(4, slash).toLowerCase();
  const system = SUPPORTED_SYSTEMS.get(type);
  if (!system) throw inputError();

  const remainder = value.slice(slash + 1);
  const at = remainder.lastIndexOf('@');
  if (at <= 0 || at === remainder.length - 1) throw inputError();

  const rawName = remainder.slice(0, at);
  const rawVersion = remainder.slice(at + 1);
  const name = packageNameFromPurl(system, rawName);
  const version = decodePart(rawVersion);
  if (!validText(version, 255) || /[\s/]/.test(version)) throw inputError();

  return Object.freeze({ type, system, name, version, purl: value });
}

function encodedPath(value) {
  return encodeURIComponent(value);
}

function validateVersionKey(value, expectedSystem = null) {
  if (!isPlainObject(value)) throw schemaError();
  const { system, name, version } = value;
  if (!validText(system, 16) || !validText(name, 512) || !validText(version, 255)) throw schemaError();
  if (expectedSystem && system !== expectedSystem) throw schemaError();
  if (!['NPM', 'CARGO', 'MAVEN', 'PYPI'].includes(system)) throw schemaError();
  return { system, name, version };
}

function validateStringArray(value, maxItems = 128, maxLength = 512) {
  if (!Array.isArray(value) || value.length > maxItems) throw schemaError();
  return value.map(item => {
    if (!validText(item, maxLength)) throw schemaError();
    return item;
  });
}

function validateAdvisories(value) {
  if (!Array.isArray(value) || value.length > 128) throw schemaError();
  return value.map(item => {
    if (!isPlainObject(item) || !validText(item.id, 128)) throw schemaError();
    return item.id;
  });
}

function purlForVersion(versionKey) {
  const { system, name, version } = validateVersionKey(versionKey);
  const encodedVersion = encodedPath(version);

  if (system === 'NPM') {
    if (name.startsWith('@')) {
      const slash = name.indexOf('/');
      if (slash <= 1 || slash === name.length - 1 || name.indexOf('/', slash + 1) !== -1) throw schemaError();
      return `pkg:npm/${encodedPath(name.slice(0, slash))}/${encodedPath(name.slice(slash + 1))}@${encodedVersion}`;
    }
    return `pkg:npm/${encodedPath(name)}@${encodedVersion}`;
  }
  if (system === 'MAVEN') {
    const colon = name.indexOf(':');
    if (colon <= 0 || colon === name.length - 1 || name.indexOf(':', colon + 1) !== -1) throw schemaError();
    return `pkg:maven/${encodedPath(name.slice(0, colon))}/${encodedPath(name.slice(colon + 1))}@${encodedVersion}`;
  }
  if (system === 'CARGO') return `pkg:cargo/${encodedPath(name)}@${encodedVersion}`;
  if (system === 'PYPI') return `pkg:pypi/${encodedPath(name)}@${encodedVersion}`;
  throw schemaError();
}

function validateVersion(raw, expected) {
  if (!isPlainObject(raw)) throw schemaError();
  const versionKey = validateVersionKey(raw.versionKey, expected.system);
  if (versionKey.name !== expected.name || versionKey.version !== expected.version) throw schemaError();
  const licenses = validateStringArray(raw.licenses);
  const advisories = validateAdvisories(raw.advisoryKeys);
  if (typeof raw.publishedAt !== 'string' || raw.publishedAt.length > 64) throw schemaError();
  if (typeof raw.isDefault !== 'boolean' || typeof raw.isDeprecated !== 'boolean') throw schemaError();
  if (typeof raw.deprecatedReason !== 'string' || raw.deprecatedReason.length > 1024) throw schemaError();
  if (!Array.isArray(raw.links) || raw.links.length > 128) throw schemaError();
  return { versionKey, licenses, advisories };
}

function validateGraph(raw, expected) {
  if (!isPlainObject(raw) || !Array.isArray(raw.nodes) || !Array.isArray(raw.edges) || typeof raw.error !== 'string') throw schemaError();
  if (raw.error) throw graphIncomplete();
  if (raw.nodes.length === 0) throw schemaError();
  if (raw.nodes.length - 1 > MAX_DEPENDENCIES || raw.edges.length > MAX_EDGES) throw graphLimit();

  const nodes = raw.nodes.map((node, index) => {
    if (!isPlainObject(node) || !Array.isArray(node.errors) || node.errors.some(error => typeof error !== 'string')) throw schemaError();
    if (node.errors.length > 0) throw graphIncomplete();
    if (typeof node.bundled !== 'boolean') throw schemaError();
    if (!['SELF', 'DIRECT', 'INDIRECT'].includes(node.relation)) throw schemaError();
    const versionKey = validateVersionKey(node.versionKey, expected.system);
    if (index === 0) {
      if (node.relation !== 'SELF' || versionKey.name !== expected.name || versionKey.version !== expected.version) throw schemaError();
    } else if (node.relation === 'SELF') {
      throw schemaError();
    }
    return { relation: node.relation, versionKey };
  });

  for (const edge of raw.edges) {
    if (!isPlainObject(edge)
      || !Number.isSafeInteger(edge.fromNode)
      || !Number.isSafeInteger(edge.toNode)
      || edge.fromNode < 0
      || edge.toNode < 0
      || edge.fromNode >= nodes.length
      || edge.toNode >= nodes.length
      || typeof edge.requirement !== 'string'
      || edge.requirement.length > 1024) {
      throw schemaError();
    }
  }

  return nodes;
}

function noResult(parsed, versionUrl) {
  return {
    observationType: 'supply_chain',
    verdict: 'no_result',
    confidence: 100,
    attributes: {
      purl: parsed.purl,
      system: parsed.system,
      name: parsed.name,
      version: parsed.version,
      publishedAt: null,
      licenses: [],
      advisories: [],
      directDependencyCount: 0,
      transitiveDependencyCount: 0,
      dependencyCount: 0,
    },
    relationships: [],
    references: [versionUrl],
  };
}

export const depsDevProvider = Object.freeze({
  name: 'deps-dev',
  types: ['package'],
  observationType: 'supply_chain',
  cacheTtlMs: 6 * 60 * 60 * 1000,
  negativeCacheTtlMs: 30 * 60 * 1000,
  costClass: 'free',
  timeoutMs: 5000,
  parserVersion: 'v3-supply-chain-2026-09-13.1',
  async run(input, { signal, fetchImpl = fetch } = {}) {
    if (input?.type !== 'package') throw inputError();
    const parsed = parsePurl(input.value);
    const systemPath = parsed.system.toLowerCase();
    const packagePath = encodedPath(parsed.name);
    const versionPath = encodedPath(parsed.version);
    const versionUrl = `${API_BASE}/systems/${systemPath}/packages/${packagePath}/versions/${versionPath}`;
    const dependenciesUrl = `${versionUrl}:dependencies`;

    let versionRaw;
    try {
      versionRaw = await fetchJson(versionUrl, { fetchImpl, signal, maxBytes: MAX_RESPONSE_BYTES });
    } catch (error) {
      if (error?.status === 404) return noResult(parsed, versionUrl);
      throw error;
    }
    const versionInfo = validateVersion(versionRaw, parsed);
    const graphRaw = await fetchJson(dependenciesUrl, { fetchImpl, signal, maxBytes: MAX_RESPONSE_BYTES });
    const nodes = validateGraph(graphRaw, parsed);

    const relationships = nodes.slice(1).map(node => ({
      targetType: 'package',
      target: purlForVersion(node.versionKey),
      relationship: node.relation === 'DIRECT' ? 'direct_dependency' : 'transitive_dependency',
    }));
    const directDependencyCount = nodes.slice(1).filter(node => node.relation === 'DIRECT').length;
    const transitiveDependencyCount = nodes.slice(1).filter(node => node.relation === 'INDIRECT').length;

    return {
      observationType: 'supply_chain',
      verdict: 'observed',
      confidence: 100,
      attributes: {
        purl: parsed.purl,
        system: versionInfo.versionKey.system,
        name: versionInfo.versionKey.name,
        version: versionInfo.versionKey.version,
        publishedAt: versionRaw.publishedAt,
        licenses: versionInfo.licenses,
        advisories: versionInfo.advisories,
        directDependencyCount,
        transitiveDependencyCount,
        dependencyCount: directDependencyCount + transitiveDependencyCount,
      },
      relationships,
      references: [versionUrl, dependenciesUrl],
    };
  },
});
