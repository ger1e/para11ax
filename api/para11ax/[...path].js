import { renderHttpError, writeVercelResponse } from '../../src/app.js';
import { requestUrl } from '../../src/core/http.js';
import { createSignedProductionSelfTestHandler } from '../../src/mcp/self-test.js';

const handleSelfTest = createSignedProductionSelfTestHandler();

function requestedPath(req) {
  const pathname = requestUrl(req)?.pathname;
  return typeof pathname === 'string' ? pathname.replace(/^\/api\/para11ax\/?/, '') : '';
}

export default async function handler(req, res) {
  if (requestedPath(req) === 'self-test') {
    const result = await handleSelfTest(req);
    writeVercelResponse(res, result);
    return;
  }
  writeVercelResponse(res, renderHttpError(req, 404, 'not_found'));
}
