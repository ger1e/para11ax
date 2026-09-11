import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

import { createSignedProductionSelfTestHandler, SELF_TEST_MESSAGE_PREFIX } from '../src/mcp/self-test.js';

const TOKEN = 'fixture-token';
const NOW_MS = 1_789_105_000_000;
const TS = Math.floor(NOW_MS / 1000);

function request() {
  const sig = createHmac('sha256', TOKEN).update(`${SELF_TEST_MESSAGE_PREFIX}${TS}`).digest('hex');
  return { method: 'GET', url: `https://example.invalid/api/para11ax/self-test?ts=${TS}&sig=${sig}`, headers: {} };
}

function toolFailure(id, message) {
  return {
    status: 200,
    body: {
      jsonrpc: '2.0',
      id,
      result: {
        resultType: 'complete',
        isError: true,
        structuredContent: { error: message },
        content: [{ type: 'text', text: message }],
      },
    },
  };
}

test('self-test classifies returned tool failures and proves generic tools/call independently', async () => {
  const calls = [];
  const mcpHandler = async req => {
    calls.push(structuredClone(req));
    if (req.body.method === 'tools/list') {
      return { status: 200, body: { jsonrpc: '2.0', id: 1, result: { tools: [
        { name: 'para11ax_enrich' }, { name: 'para11ax_user_scan' }, { name: 'para11ax_command' },
        ...Array.from({ length: 10 }, (_, i) => ({ name: `tool_${i}` })),
      ] } } };
    }
    if (req.body.params?.name === 'para11ax_enrich') return toolFailure(2, 'internal failure with details that must not leak');
    if (req.body.params?.name === 'para11ax_user_scan') return toolFailure(3, 'worker failure with details that must not leak');
    if (req.body.params?.name === 'para11ax_command') {
      return { status: 200, body: { jsonrpc: '2.0', id: 4, result: {
        resultType: 'complete', isError: false,
        structuredContent: { command: 'intel.validate', output: { value: { valid: true, type: 'ip', value: '1.1.1.1' } } },
      } } };
    }
    throw new Error('unexpected request');
  };

  const handle = createSignedProductionSelfTestHandler({
    env: {
      PARA11AX_TOKEN: TOKEN,
      PARA11AX_USER_SCANNER_URL: 'https://worker.example/scan',
    },
    nowMs: () => NOW_MS,
    mcpHandler,
  });

  const result = await handle(request());
  assert.equal(result.status, 200);
  assert.equal(result.body.status, 'fail');
  assert.equal(result.body.enrichment.failureClass, 'tool_error');
  assert.equal(result.body.userScanner.failureClass, 'tool_error');
  assert.deepEqual(result.body.diagnostics, {
    genericToolCall: 'pass',
    userScannerUrlConfigured: true,
    userScannerTokenConfigured: false,
  });
  assert.equal(calls.length, 4);
  assert.equal(calls[3].body.params.name, 'para11ax_command');
  assert.deepEqual(calls[3].body.params.arguments, { commandId: 'intel.validate', args: ['1.1.1.1'] });
  const serialized = JSON.stringify(result.body);
  assert.equal(serialized.includes('internal failure with details'), false);
  assert.equal(serialized.includes('worker failure with details'), false);
});

test('self-test distinguishes an MCP transport exception from a returned tool error', async () => {
  let call = 0;
  const mcpHandler = async req => {
    call += 1;
    if (call === 1) return { status: 200, body: { result: { tools: [
      { name: 'para11ax_enrich' }, { name: 'para11ax_user_scan' }, { name: 'para11ax_command' },
      ...Array.from({ length: 10 }, (_, i) => ({ name: `tool_${i}` })),
    ] } } };
    if (req.body.params?.name === 'para11ax_enrich') throw new TypeError('sensitive implementation detail');
    if (req.body.params?.name === 'para11ax_user_scan') return toolFailure(3, 'safe_code');
    if (req.body.params?.name === 'para11ax_command') return toolFailure(4, 'probe failed');
    throw new Error('unexpected');
  };

  const handle = createSignedProductionSelfTestHandler({ env: { PARA11AX_TOKEN: TOKEN }, nowMs: () => NOW_MS, mcpHandler });
  const result = await handle(request());
  assert.equal(result.body.enrichment.failureClass, 'transport_exception');
  assert.equal(result.body.userScanner.failureClass, 'tool_error');
  assert.equal(result.body.diagnostics.genericToolCall, 'fail');
  assert.equal(JSON.stringify(result.body).includes('sensitive implementation detail'), false);
});
