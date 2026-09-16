const MODES = new Set(['enrich', 'graph', 'search', 'monitor', 'analysis', 'knowledge']);
const SENSITIVITY = new Set(['public', 'owned_asset', 'pii', 'credential', 'secret', 'sample']);
const AUTHORIZATION = new Set(['none', 'tenant', 'verified_domain', 'owned_network', 'explicit_case', 'explicit_action']);
const RETENTION = new Set(['normal', 'restricted', 'ephemeral', 'no_store']);

function valueFromSet(name, field, value, allowed, fallback) {
  const candidate = value ?? fallback;
  if (!allowed.has(candidate)) throw new Error(`invalid provider manifest: ${name}.${field}`);
  return candidate;
}

export function normalizeCapabilityPolicy(name, input) {
  const mode = valueFromSet(name, 'mode', input.mode, MODES, 'enrich');
  const sensitivity = valueFromSet(name, 'sensitivity', input.sensitivity, SENSITIVITY, 'public');
  const authorization = valueFromSet(name, 'authorization', input.authorization, AUTHORIZATION, 'none');
  const retentionClass = valueFromSet(name, 'retentionClass', input.retentionClass, RETENTION, 'normal');
  const fanoutEligible = input.fanoutEligible ?? (mode === 'enrich' && sensitivity === 'public' && authorization === 'none');
  if (typeof fanoutEligible !== 'boolean') throw new Error(`invalid provider manifest: ${name}.fanoutEligible`);
  if (fanoutEligible && (mode !== 'enrich' || sensitivity !== 'public' || authorization !== 'none')) {
    throw new Error(`invalid provider manifest: ${name}.fanoutEligible privileged capability`);
  }
  return Object.freeze({ mode, fanoutEligible, sensitivity, authorization, retentionClass });
}

export function boundedCapabilityInteger(name, field, value, max) {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || value < 1 || value > max) throw new Error(`invalid provider manifest: ${name}.${field}`);
  return value;
}
