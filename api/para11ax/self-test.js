import { writeVercelResponse } from '../../src/app.js';
import { createSignedProductionSelfTestHandler } from '../../src/mcp/self-test.js';

const handle = createSignedProductionSelfTestHandler();

export default async function handler(req, res) {
  const result = await handle(req);
  writeVercelResponse(res, result);
}
