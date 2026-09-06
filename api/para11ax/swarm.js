import { createGreyNoiseSwarmCommandHandler } from '../../src/greynoise-swarm-command.js';
import { writeVercelResponse } from '../../src/app.js';

const handleSwarm = createGreyNoiseSwarmCommandHandler();

export default async function handler(req, res) {
  const result = await handleSwarm(req);
  if (!result?.binary) {
    writeVercelResponse(res, result);
    return;
  }
  res.status(result.status);
  for (const [name, value] of Object.entries(result.headers ?? {})) res.setHeader(name, value);
  res.end(Buffer.from(result.body));
}
