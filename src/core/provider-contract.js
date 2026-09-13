import { EXECUTION_POLICY_VERSION } from './execution-policy.js';
import { INTELLIGENCE_ONLY_OBSERVABLE_MANIFEST } from './intelligence-observable-registry.js';

const METHODS = new Set(['GET', 'POST']);
const SOURCE_ROLES = new Set(['authoritative', 'first_party', 'aggregator', 'community', 'contextual']);
const FRESHNESS = new Set(['live', 'near_real_time', 'periodic', 'reference']);

function sameStrings(a, b) {
  return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((value, index) => value === b[index]);
}

function fail(name, reason) {
  throw new TypeError(`provider ${name}: ${reason}`);
}

export function assertProviderContract({ adapter, policy, observableRegistry }) {
  const name = adapter?.name ?? 'unknown';
  if (!adapter) fail(name, 'adapter is required');
  if (!policy) fail(name, 'missing canonical policy');
  if (!observableRegistry || typeof observableRegistry !== 'object') fail(name, 'observable registry is required');

  for (const type of policy.types ?? []) {
    if (!Object.hasOwn(observableRegistry, type)) fail(name, `unknown observable type ${type}`);
  }

  for (const field of ['types', 'observationTypes', 'fixedHosts', 'methods', 'protocols']) {
    if (!sameStrings(adapter[field], policy[field])) fail(name, `${field} policy mismatch`);
  }

  if (!adapter.protocols.every(protocol => protocol === 'https:')) fail(name, 'https-only protocol required');
  if (!adapter.methods.every(method => METHODS.has(method))) fail(name, 'unsupported method');
  if (!SOURCE_ROLES.has(policy.sourceRole)) fail(name, 'invalid sourceRole');
  if (!FRESHNESS.has(policy.freshnessClass)) fail(name, 'invalid freshnessClass');
  if (policy.admissionVersion !== 'v8.1') fail(name, 'invalid admissionVersion');
  if (policy.executionPolicy !== EXECUTION_POLICY_VERSION) fail(name, 'invalid executionPolicy');
  if (adapter.sourceRole !== policy.sourceRole) fail(name, 'sourceRole policy mismatch');
  if (adapter.freshnessClass !== policy.freshnessClass) fail(name, 'freshnessClass policy mismatch');
  if (adapter.admissionVersion !== policy.admissionVersion) fail(name, 'admissionVersion policy mismatch');
  if (adapter.executionPolicy !== policy.executionPolicy) fail(name, 'executionPolicy policy mismatch');
  if (adapter.distribution !== policy.distribution) fail(name, 'distribution policy mismatch');
  if (typeof adapter.run !== 'function') fail(name, 'run function required');
  return true;
}

export function validateProviderSet({ adapters, manifest, observableRegistry }) {
  if (!Array.isArray(adapters)) throw new TypeError('adapters are required');
  if (!manifest || typeof manifest !== 'object') throw new TypeError('provider manifest is required');
  const providerObservableRegistry = Object.freeze({
    ...observableRegistry,
    ...INTELLIGENCE_ONLY_OBSERVABLE_MANIFEST,
  });
  const names = [];
  const types = new Set();
  for (const adapter of adapters) {
    const policy = manifest[adapter.name];
    assertProviderContract({ adapter, policy, observableRegistry: providerObservableRegistry });
    names.push(adapter.name);
    for (const type of adapter.types) types.add(type);
  }
  return Object.freeze({
    providerNames: Object.freeze([...names].sort()),
    observableTypes: Object.freeze([...types].sort()),
  });
}
