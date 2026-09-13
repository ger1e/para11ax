import { createApp, writeVercelResponse } from '../../src/app.js';

const app = createApp();

export default async function handler(req, res) {
  const result = await app.handleIntelligence(req);
  writeVercelResponse(res, result);
}
