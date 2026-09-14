import { domainToASCII } from 'node:url';
import { parseCanonicalCidr } from './network.js';

const TRUSTED = Symbol('para11ax.trusted-authorization-context');
const MAX_SCOPE_ITEMS = 32;
const MODES = new Set(['enrich','graph','search','monitor','analysis','knowledge','sensitive']);

function fail(field) {
  throw new TypeError(`invalid authorization context: ${field}`);
}

function boundedString(value, field, max = 256, pattern = null) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || value.length < 1 || value.length > max || (pattern && !pattern.test(value))) fail(field);
  return value;
}

function canonicalDomain(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 253 || /\s/.test(value)) return null;
  const ascii = domainToASCII(value.toLowerCase());
  if (!ascii || !ascii.includes('.') || ascii.length > 253) return null;
  const labels = ascii.split('.');
  if (labels.some(label => !label || label.length > 63 || !/^[a-z0-9-]+$/.test(label) || label.startsWith('-') || label.endsWith('-'))) return null;
  return ascii;
}

function boundedUniqueArray(value, field, normalize) {
  if (value === undefined) return Object.freeze([]);
  if (!Array.isArray(value) || value.length > MAX_SCOPE_ITEMS) fail(field);
  const output = [];
  const seen = new Set();
  for (const item of value) {
    const normalized = normalize(item);
    if (normalized === null) fail(field);
    if (!seen.has(normalized)) {
      seen.add(normalized);
      output.push(normalized);
    }
  }
  output.sort();
  return Object.freeze(output);
}

function normalize(input, trustMarker) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('root');
  const principal = boundedString(input.principal, 'principal', 256, /^[A-Za-z0-9@._:+-]+$/);
  const caseId = boundedString(input.caseId, 'caseId', 128, /^[A-Za-z0-9._:-]+$/);
  const tenant = boundedString(input.tenant, 'tenant', 128, /^[A-Za-z0-9._:-]+$/);
  if (input.explicitAnalysis !== undefined && typeof input.explicitAnalysis !== 'boolean') fail('explicitAnalysis');
  const requestedMode = input.requestedMode === undefined || input.requestedMode === null ? null : input.requestedMode;
  if (requestedMode !== null && !MODES.has(requestedMode)) fail('requestedMode');

  const verifiedDomains = boundedUniqueArray(input.verifiedDomains, 'verifiedDomains', canonicalDomain);
  const ownedCidrs = boundedUniqueArray(input.ownedCidrs, 'ownedCidrs', value => {
    const parsed = parseCanonicalCidr(value);
    return parsed && parsed.cidr === value ? parsed.cidr : null;
  });

  return Object.freeze({
    trusted: trustMarker === TRUSTED,
    principal,
    caseId,
    verifiedDomains,
    ownedCidrs,
    tenant,
    explicitAnalysis: input.explicitAnalysis === true,
    requestedMode,
  });
}

export function normalizeAuthorizationContext(input = {}) {
  return normalize(input, null);
}

export function createTrustedAuthorizationContext(input = {}) {
  return normalize(input, TRUSTED);
}
