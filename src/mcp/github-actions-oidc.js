import { createPublicKey, verify as verifySignature } from 'node:crypto';

export const GITHUB_OIDC_ISSUER = 'https://token.actions.githubusercontent.com';
export const GITHUB_OIDC_JWKS_URL = `${GITHUB_OIDC_ISSUER}/.well-known/jwks`;
export const PRODUCTION_SMOKE_AUDIENCE = 'para11ax-production-smoke';

const TRUST = Object.freeze({
  repository: 'ger1e/para11ax',
  repositoryId: '1339112568',
  repositoryOwnerId: '121339626',
  ref: 'refs/heads/main',
  workflowRef: 'ger1e/para11ax/.github/workflows/production-mcp-smoke.yml@refs/heads/main',
  repositoryVisibility: 'public',
});
const ALLOWED_EVENTS = new Set(['push', 'workflow_dispatch']);
const MAX_JWT_BYTES = 16 * 1024;
const MAX_JWKS_BYTES = 64 * 1024;
const MAX_TOKEN_AGE_SECONDS = 10 * 60;
const CLOCK_SKEW_SECONDS = 30;

function decodeJsonSegment(value) {
  if (typeof value !== 'string' || value.length < 2 || value.length > MAX_JWT_BYTES) throw new Error('invalid_oidc_token');
  const text = Buffer.from(value, 'base64url').toString('utf8');
  const parsed = JSON.parse(text);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('invalid_oidc_token');
  return parsed;
}

function audienceMatches(value) {
  if (typeof value === 'string') return value === PRODUCTION_SMOKE_AUDIENCE;
  return Array.isArray(value) && value.length <= 4 && value.includes(PRODUCTION_SMOKE_AUDIENCE);
}

function claimsTrusted(claims, nowSeconds) {
  if (claims.iss !== GITHUB_OIDC_ISSUER || !audienceMatches(claims.aud)) return false;
  if (claims.repository !== TRUST.repository || String(claims.repository_id) !== TRUST.repositoryId) return false;
  if (String(claims.repository_owner_id) !== TRUST.repositoryOwnerId) return false;
  if (claims.repository_visibility !== TRUST.repositoryVisibility) return false;
  if (claims.ref !== TRUST.ref || String(claims.ref_protected) !== 'true') return false;
  if (!ALLOWED_EVENTS.has(claims.event_name) || claims.workflow_ref !== TRUST.workflowRef) return false;

  const iat = Number(claims.iat);
  const nbf = Number(claims.nbf);
  const exp = Number(claims.exp);
  if (![iat, nbf, exp].every(Number.isFinite)) return false;
  if (iat > nowSeconds + CLOCK_SKEW_SECONDS || nbf > nowSeconds + CLOCK_SKEW_SECONDS) return false;
  if (exp <= nowSeconds - CLOCK_SKEW_SECONDS) return false;
  if (nowSeconds - iat > MAX_TOKEN_AGE_SECONDS || exp - iat > MAX_TOKEN_AGE_SECONDS + CLOCK_SKEW_SECONDS) return false;
  return true;
}

async function readJwks(fetchImpl) {
  const response = await fetchImpl(GITHUB_OIDC_JWKS_URL, {
    method: 'GET',
    headers: { accept: 'application/json' },
    redirect: 'error',
    cache: 'no-store',
    signal: AbortSignal.timeout(5_000),
  });
  if (!response?.ok) throw new Error('oidc_jwks_unavailable');
  const text = await response.text();
  if (Buffer.byteLength(text, 'utf8') > MAX_JWKS_BYTES) throw new Error('oidc_jwks_oversized');
  const payload = JSON.parse(text);
  if (!payload || !Array.isArray(payload.keys) || payload.keys.length > 32) throw new Error('oidc_jwks_invalid');
  return payload.keys;
}

export async function verifyGitHubActionsOidc(token, { fetchImpl = fetch, nowMs = () => Date.now() } = {}) {
  try {
    if (typeof token !== 'string' || !token || Buffer.byteLength(token, 'utf8') > MAX_JWT_BYTES) return false;
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    const header = decodeJsonSegment(encodedHeader);
    const claims = decodeJsonSegment(encodedPayload);
    if (header.alg !== 'RS256' || header.typ !== 'JWT' || typeof header.kid !== 'string' || !header.kid || header.kid.length > 256) return false;
    if (!claimsTrusted(claims, Math.floor(nowMs() / 1000))) return false;

    const keys = await readJwks(fetchImpl);
    const jwk = keys.find(key => key?.kid === header.kid && key?.kty === 'RSA' && (!key.alg || key.alg === 'RS256') && (!key.use || key.use === 'sig'));
    if (!jwk) return false;
    const publicKey = createPublicKey({ key: jwk, format: 'jwk' });
    const signature = Buffer.from(encodedSignature, 'base64url');
    if (!signature.length || signature.length > 1024) return false;
    return verifySignature('RSA-SHA256', Buffer.from(`${encodedHeader}.${encodedPayload}`), publicKey, signature);
  } catch {
    return false;
  }
}
