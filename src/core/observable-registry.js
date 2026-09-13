import rawManifest from '../../config/observables.json' with { type: 'json' };

const CATEGORIES = new Set(['infrastructure', 'artifact', 'vulnerability', 'knowledge']);
const CANONICALIZATION = new Set(['ip', 'idna-domain', 'http-url', 'md5-sha1-sha256', 'cert-sha256', 'cve', 'attack-id', 'asn', 'cidr']);
const STIX_EXPORT = new Set(['indicator', 'vulnerability', 'evidence-object', 'unsupported']);

function fail(message) {
  throw new Error(`invalid observable manifest: ${message}`);
}

function validate(type, input) {
  if (!/^[a-z][a-z0-9-]{1,31}$/.test(type)) fail(`type ${type}`);
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail(type);
  if (typeof input.displayName !== 'string' || input.displayName.length < 1 || input.displayName.length > 80) fail(`${type}.displayName`);
  if (!CATEGORIES.has(input.category)) fail(`${type}.category`);
  if (!CANONICALIZATION.has(input.canonicalization)) fail(`${type}.canonicalization`);
  if (!Number.isSafeInteger(input.maxLength) || input.maxLength < 1 || input.maxLength > 4096) fail(`${type}.maxLength`);
  if (!STIX_EXPORT.has(input.stixExport)) fail(`${type}.stixExport`);
  if (typeof input.active !== 'boolean') fail(`${type}.active`);
  return Object.freeze({ ...input });
}

export const OBSERVABLE_MANIFEST = Object.freeze(Object.fromEntries(
  Object.entries(rawManifest).map(([type, policy]) => [type, validate(type, policy)]),
));

export function observablePolicy(type) {
  const policy = OBSERVABLE_MANIFEST[type];
  if (!policy) throw new Error(`unknown observable type: ${String(type)}`);
  return policy;
}

export function observableTypes() {
  return Object.freeze(Object.keys(OBSERVABLE_MANIFEST).sort());
}

export function isObservableType(type) {
  return typeof type === 'string' && Object.hasOwn(OBSERVABLE_MANIFEST, type);
}
