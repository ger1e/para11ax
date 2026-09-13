const MODES = new Set(['enrich','graph','search','monitor','analysis','knowledge','sensitive']);
const SENSITIVITY = new Set(['public','owned_asset','pii','credential','secret','sample']);
const AUTHORIZATION = new Set(['none','tenant','verified_domain','owned_network','explicit_case','explicit_action']);
const RETENTION = new Set(['normal','restricted','ephemeral','no_store']);
const FIELDS = Object.freeze(['mode','fanoutEligible','sensitivity','authorization','retentionClass']);

export const LEGACY_CAPABILITY_BASELINE = Object.freeze({
  mode: 'enrich',
  fanoutEligible: true,
  sensitivity: 'public',
  authorization: 'none',
  retentionClass: 'normal',
});

function invalid(name, field) {
  throw new Error(`invalid provider manifest: ${name}.${field}`);
}

export function normalizeCapabilityPolicy(name, input = {}) {
  const present = FIELDS.filter(field => input[field] !== undefined);
  if (present.length === 0) return LEGACY_CAPABILITY_BASELINE;
  if (present.length !== FIELDS.length) invalid(name, 'capability policy incomplete');
  if (!MODES.has(input.mode)) invalid(name, 'mode');
  if (typeof input.fanoutEligible !== 'boolean') invalid(name, 'fanoutEligible');
  if (!SENSITIVITY.has(input.sensitivity)) invalid(name, 'sensitivity');
  if (!AUTHORIZATION.has(input.authorization)) invalid(name, 'authorization');
  if (!RETENTION.has(input.retentionClass)) invalid(name, 'retentionClass');
  if (input.fanoutEligible && (input.mode !== 'enrich' || input.authorization !== 'none' || input.sensitivity !== 'public')) {
    invalid(name, 'fanoutEligible privileged capability');
  }
  return Object.freeze({
    mode: input.mode,
    fanoutEligible: input.fanoutEligible,
    sensitivity: input.sensitivity,
    authorization: input.authorization,
    retentionClass: input.retentionClass,
  });
}

export function boundedCapabilityInteger(name, field, value, max) {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || value < 1 || value > max) invalid(name, field);
  return value;
}
