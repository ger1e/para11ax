import { createApp, renderHttpError, writeVercelResponse } from '../../src/app.js';
import { requestUrl } from '../../src/core/http.js';
import { createSignedProductionSelfTestHandler } from '../../src/mcp/self-test.js';

const app = createApp();
const handleSelfTest = createSignedProductionSelfTestHandler();

function requestedPath(req) {
  const pathname = requestUrl(req)?.pathname;
  return typeof pathname === 'string' ? pathname.replace(/^\/api\/para11ax\/?/, '') : '';
}

export default async function handler(req, res) {
  const path = requestedPath(req);
  if (path === 'intelligence') {
    const result = await app.handleIntelligence(req);
    writeVercelResponse(res, result);
    return;
  }
  if (path === 'self-test') {
    const result = await handleSelfTest(req);
    writeVercelResponse(res, result);
    return;
  }
  writeVercelResponse(res, renderHttpError(req, 404, 'not_found'));
}
