const SCOPES = new Set(['workspace', 'demo']);
const EXPORT_TYPES = Object.freeze({ pcap: 'pcap', 'raw-source': 'rawSource', 'raw-destination': 'rawDestination' });
const SESSION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const ISO8601 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;

function fail(message) { throw new TypeError(message); }
function validTime(value) { return ISO8601.test(value) && Number.isFinite(Date.parse(value)); }

export function parseSwarmArgs(args) {
  const command = String(args[0] ?? '').toLowerCase();
  if (!['search', 'get', 'export'].includes(command)) fail('usage: swarm <search|get|export> ...');
  let scope = 'workspace';

  if (command === 'get') {
    const sessionId = String(args[1] ?? '').trim();
    if (!SESSION_ID.test(sessionId)) fail('usage: swarm get <session-id> [--scope <workspace|demo>]');
    if (args.length === 2) return { command, sessionId, scope, startTime: null, endTime: null, query: null, page: null, pageSize: null, exportType: null };
    if (args.length !== 4 || args[2] !== '--scope') fail('usage: swarm get <session-id> [--scope <workspace|demo>]');
    scope = String(args[3] ?? '').toLowerCase();
    if (!SCOPES.has(scope)) fail('swarm scope must be workspace or demo');
    return { command, sessionId, scope, startTime: null, endTime: null, query: null, page: null, pageSize: null, exportType: null };
  }

  if (command === 'export') {
    const sessionId = String(args[1] ?? '').trim();
    const exportType = EXPORT_TYPES[String(args[2] ?? '').toLowerCase()];
    if (args.length !== 3 || !SESSION_ID.test(sessionId) || !exportType) fail('usage: swarm export <session-id> <pcap|raw-source|raw-destination>');
    return { command, sessionId, scope, startTime: null, endTime: null, query: null, page: null, pageSize: null, exportType };
  }

  let startTime = null;
  let endTime = null;
  let query = null;
  let page = 1;
  let pageSize = 25;
  for (let index = 1; index < args.length; index += 1) {
    const flag = String(args[index]);
    if (!['--from', '--to', '--scope', '--query', '--page', '--page-size'].includes(flag)) fail(`unsupported swarm option: ${flag}`);
    const raw = args[index + 1];
    if (raw === undefined || String(raw).startsWith('--')) fail(`${flag} requires a value`);
    const value = String(raw).trim();
    if (flag === '--from') startTime = value;
    else if (flag === '--to') endTime = value;
    else if (flag === '--scope') {
      scope = value.toLowerCase();
      if (!SCOPES.has(scope)) fail('swarm scope must be workspace or demo');
    } else if (flag === '--query') {
      if (!value || value.length > 2048 || /[\u0000-\u001f\u007f]/.test(value)) fail('swarm query must be 1..2048 printable characters');
      query = value;
    } else if (flag === '--page') {
      page = Number(value);
      if (!Number.isSafeInteger(page) || page < 1 || page > 10000) fail('swarm page must be 1..10000');
    } else {
      pageSize = Number(value);
      if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > 100) fail('swarm page-size must be 1..100');
    }
    index += 1;
  }
  if (!startTime || !endTime || !validTime(startTime) || !validTime(endTime) || Date.parse(startTime) >= Date.parse(endTime)) fail('swarm search requires valid --from and --to ISO-8601 timestamps with from < to');
  return { command, sessionId: null, scope, startTime, endTime, query, page, pageSize, exportType: null };
}

export const SWARM_COMPLETIONS = Object.freeze(['search', 'get', 'export']);
