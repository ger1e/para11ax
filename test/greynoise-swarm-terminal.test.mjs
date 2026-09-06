import assert from 'node:assert/strict';
import test from 'node:test';

import { COMMANDS, interpretCommand } from '../app/shell.js';

test('terminal exposes a bounded GreyNoise Swarm session surface', () => {
  const names = new Set(COMMANDS.map(item => item.name));
  assert.ok(names.has('swarm'));

  assert.deepEqual(
    interpretCommand('swarm get session-123 --scope demo', { authenticated: true }),
    { action: 'swarm', command: 'get', sessionId: 'session-123', scope: 'demo', startTime: null, endTime: null, query: null, page: null, pageSize: null, exportType: null, historySafe: true },
  );

  assert.deepEqual(
    interpretCommand('swarm search --from 2026-09-05T00:00:00Z --to 2026-09-06T00:00:00Z --scope workspace --query "classification:malicious" --page-size 50', { authenticated: true }),
    { action: 'swarm', command: 'search', sessionId: null, scope: 'workspace', startTime: '2026-09-05T00:00:00Z', endTime: '2026-09-06T00:00:00Z', query: 'classification:malicious', page: 1, pageSize: 50, exportType: null, historySafe: true },
  );

  assert.deepEqual(
    interpretCommand('swarm export session-123 raw-source', { authenticated: true }),
    { action: 'swarm', command: 'export', sessionId: 'session-123', scope: 'workspace', startTime: null, endTime: null, query: null, page: null, pageSize: null, exportType: 'rawSource', historySafe: true },
  );
});
