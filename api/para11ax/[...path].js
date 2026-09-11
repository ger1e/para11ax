import { renderHttpError, writeVercelResponse } from '../../src/app.js';
import { createSignedProductionSelfTestHandler } from '../../src/mcp/self-test.js';

const handleSelfTest = createSignedProductionSelfTestHandler();

function requestedPath(req) {
  const raw = req?.query?.path;
  if (Array.isArray(raw)) return raw.join('/');
  if (typeof raw === 'string') return raw;
  try {
    const pathname = new URL(req?.url ?? '', 'https://para11ax.invalid').pathname;
    return pathname.replace(/^\/api\/para11ax\/?/, '');
  } catch {
    return '';
  }
}

export default async function handler(req, res) {
  if (requestedPath(req) === 'self-test') {
    const result = await handleSelfTest(req);
    writeVercelResponse(res, result);
    return;
  }
  writeVercelResponse(res, renderHttpError(req, 404, 'not_found'));
}
