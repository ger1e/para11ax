import { createApp, writeVercelResponse } from '../../src/app.js';

const app = createApp();
const DOCUMENTATION_URL = 'https://github.com/ger1e/para11ax/blob/main/docs/API.md';
const SECURITY_URL = 'https://para11ax.vercel.app/.well-known/security.txt';

export function sanitizePublicMeta(result) {
  if (!result || result.status !== 200 || !result.body || typeof result.body !== 'object') return result;
  const { gatewayVersion, schemaVersion, types, profiles } = result.body;
  return {
    ...result,
    body: {
      gatewayVersion,
      schemaVersion,
      types: Array.isArray(types) ? [...types] : [],
      profiles: Array.isArray(profiles) ? [...profiles] : [],
      documentation: DOCUMENTATION_URL,
      security: SECURITY_URL,
    },
  };
}

export default async function handler(req, res) {
  const result = sanitizePublicMeta(await app.handleMeta(req));
  writeVercelResponse(res, result);
}
