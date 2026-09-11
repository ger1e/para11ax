import { createMcpHttpHandler } from '../src/mcp/transport.js';

const handleMcp = createMcpHttpHandler();

export default async function handler(req, res) {
  const result = await handleMcp(req);
  res.status(result.status);
  for (const [name, value] of Object.entries(result.headers ?? {})) res.setHeader(name, value);
  if (result.body === null || result.body === undefined) {
    res.end();
    return;
  }
  res.end(JSON.stringify(result.body));
}
