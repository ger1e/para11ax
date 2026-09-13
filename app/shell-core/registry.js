import { VALUE_TYPES } from './types.js';
import { DOMAIN_INVESTIGATION_COMMAND_DESCRIPTORS } from './domain-investigation-catalog.js';

const SURFACES = new Set(['web', 'cli']);
const AUTH_MODES = new Set(['none', 'optional', 'required']);
const EGRESS_CLASSES = new Set(['none', 'gateway', 'provider']);
const SIDE_EFFECTS = new Set(['none', 'session', 'browser-download', 'filesystem', 'local-admin']);
const NAMESPACES = new Set(['discovery', 'session', 'system', 'intel', 'provider', 'osint', 'result', 'mission', 'domain-investigation', 'case', 'investigation', 'report', 'export', 'terminal', 'transform']);
const FORBIDDEN_HOST_ROOTS = new Set(['sudo', 'ssh', 'curl', 'wget', 'eval', 'exec', 'source']);

function nonEmptyString(value, label) {
  if (typeof value !== 'string' || !value.trim()) throw new TypeError(`${label} is required`);
  return value.trim();
}

function tokenSequence(value, label) {
  if (!Array.isArray(value) || value.length === 0 || value.some(token => typeof token !== 'string' || !token.trim())) {
    throw new TypeError(`${label} must be a non-empty token sequence`);
  }
  return Object.freeze(value.map(token => token.toLowerCase()));
}

function stringList(value, label, { allowEmpty = true } = {}) {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0) || value.some(item => typeof item !== 'string' || !item.trim())) {
    throw new TypeError(`${label} must be a string array`);
  }
  return Object.freeze(value.map(item => item.trim()));
}

function rejectForbiddenRoot(sequence, id) {
  const root = String(sequence[0] ?? '').toLowerCase();
  if (FORBIDDEN_HOST_ROOTS.has(root)) throw new TypeError(`command ${id} uses forbidden host command root: ${root}`);
}

function normalizeDescriptor(source) {
  if (!source || typeof source !== 'object' || Array.isArray(source)) throw new TypeError('command descriptor object required');
  const id = nonEmptyString(source.id, 'command id');
  const tokens = tokenSequence(source.tokens, `command ${id} tokens`);
  const aliases = source.aliases === undefined ? [] : source.aliases;
  if (!Array.isArray(aliases)) throw new TypeError(`command ${id} aliases must be an array`);
  const frozenAliases = Object.freeze(aliases.map((alias, index) => tokenSequence(alias, `command ${id} alias ${index}`)));
  rejectForbiddenRoot(tokens, id);
  for (const alias of frozenAliases) rejectForbiddenRoot(alias, id);
  const namespace = nonEmptyString(source.namespace, `command ${id} namespace`);
  if (!NAMESPACES.has(namespace)) throw new TypeError(`command ${id} namespace is invalid`);

  const surfaces = stringList(source.surfaces, `command ${id} surfaces`, { allowEmpty: false });
  if (new Set(surfaces).size !== surfaces.length || surfaces.some(surface => !SURFACES.has(surface))) {
    throw new TypeError(`command ${id} surface metadata is invalid`);
  }

  const auth = nonEmptyString(source.auth, `command ${id} auth`);
  if (!AUTH_MODES.has(auth)) throw new TypeError(`command ${id} auth mode is invalid`);

  const inputTypes = stringList(source.inputTypes, `command ${id} input types`, { allowEmpty: false });
  if (inputTypes.some(type => !VALUE_TYPES.includes(type))) throw new TypeError(`command ${id} input type is invalid`);
  const outputType = nonEmptyString(source.outputType, `command ${id} output type`);
  if (!VALUE_TYPES.includes(outputType)) throw new TypeError(`command ${id} output type is invalid`);

  const egressClass = nonEmptyString(source.egressClass, `command ${id} egress class`);
  if (!EGRESS_CLASSES.has(egressClass)) throw new TypeError(`command ${id} egress class is invalid`);
  const sideEffect = nonEmptyString(source.sideEffect, `command ${id} side effect`);
  if (!SIDE_EFFECTS.has(sideEffect)) throw new TypeError(`command ${id} side effect is invalid`);

  const capabilities = stringList(source.capabilities ?? [], `command ${id} capabilities`);
  const handler = nonEmptyString(source.handler, `command ${id} handler`);
  const usage = nonEmptyString(source.usage, `command ${id} usage`);
  const summary = nonEmptyString(source.summary, `command ${id} summary`);

  return Object.freeze({
    ...source,
    id,
    tokens,
    aliases: frozenAliases,
    namespace,
    surfaces,
    auth,
    inputTypes,
    outputType,
    egressClass,
    sideEffect,
    capabilities,
    handler,
    usage,
    summary,
  });
}

function sequenceKey(tokens) {
  return tokens.join('\u0000');
}

function canonicalBuiltins(descriptors) {
  const ids = new Set(descriptors.map(item => item?.id));
  const canonicalCatalog = ids.has('discovery.help') && ids.has('mission.new') && ids.has('investigation.show');
  if (!canonicalCatalog || ids.has('domain-investigation.build')) return descriptors;
  return [...descriptors, ...DOMAIN_INVESTIGATION_COMMAND_DESCRIPTORS];
}

export function createCommandRegistry(descriptors = []) {
  if (!Array.isArray(descriptors)) throw new TypeError('command descriptors must be an array');

  const items = Object.freeze(canonicalBuiltins(descriptors).map(normalizeDescriptor));
  const byId = new Map();
  const sequences = new Map();

  for (const descriptor of items) {
    if (byId.has(descriptor.id)) throw new TypeError(`duplicate command id: ${descriptor.id}`);
    byId.set(descriptor.id, descriptor);
    for (const sequence of [descriptor.tokens, ...descriptor.aliases]) {
      const key = sequenceKey(sequence);
      if (sequences.has(key)) throw new TypeError(`duplicate command token sequence: ${sequence.join(' ')}`);
      sequences.set(key, descriptor);
    }
  }

  const orderedSequences = Object.freeze([...sequences.entries()]
    .map(([key, descriptor]) => ({ key, tokens: Object.freeze(key.split('\u0000')), descriptor }))
    .sort((a, b) => b.tokens.length - a.tokens.length || a.key.localeCompare(b.key)));

  return Object.freeze({
    all() { return items; },
    list({ surface = null, namespace = null } = {}) {
      if (surface !== null && !SURFACES.has(surface)) throw new TypeError(`invalid command surface: ${surface}`);
      if (namespace !== null && !NAMESPACES.has(namespace)) throw new TypeError(`invalid command namespace: ${namespace}`);
      return Object.freeze(items.filter(item => (surface === null || item.surfaces.includes(surface)) && (namespace === null || item.namespace === namespace)));
    },
    get(id) { return byId.get(id); },
    resolve(tokens, surface = null) {
      if (!Array.isArray(tokens)) throw new TypeError('command tokens must be an array');
      if (surface !== null && !SURFACES.has(surface)) throw new TypeError(`invalid command surface: ${surface}`);
      const normalized = tokens.map(token => String(token).toLowerCase());
      for (const entry of orderedSequences) {
        if (entry.tokens.length > normalized.length) continue;
        let match = true;
        for (let index = 0; index < entry.tokens.length; index += 1) {
          if (entry.tokens[index] !== normalized[index]) { match = false; break; }
        }
        if (!match) continue;
        return Object.freeze({
          descriptor: entry.descriptor,
          args: Object.freeze(tokens.slice(entry.tokens.length)),
          surfaceAvailable: surface === null || entry.descriptor.surfaces.includes(surface),
        });
      }
      return null;
    },
    byNamespace(namespace) { return Object.freeze(items.filter(item => item.namespace === namespace)); },
    forSurface(surface) {
      if (!SURFACES.has(surface)) throw new TypeError(`invalid command surface: ${surface}`);
      return Object.freeze(items.filter(item => item.surfaces.includes(surface)));
    },
  });
}
