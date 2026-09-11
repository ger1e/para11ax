import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const workerRoot = path.join(root, 'workers', 'user-scanner');

const probe = String.raw`
import importlib.util
import pathlib
import sys
import types

root = pathlib.Path('.').resolve()
stub_worker = types.ModuleType('worker')
stub_worker.run_scan = lambda payload: {'summary': {}, 'results': [], 'errored_sites': []}
sys.modules['worker'] = stub_worker

spec = importlib.util.spec_from_file_location('user_scanner_api', root / 'api' / 'index.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

health = module.handler.__new__(module.handler)
health.path = '/health?_vercel_share=temporary-token'
health_responses = []
health._json = lambda status, body: health_responses.append((status, body))
health.do_GET()
assert health_responses == [(200, {'status': 'ok', 'service': 'user-scanner'})], health_responses

scan = module.handler.__new__(module.handler)
scan.path = '/scan?_vercel_share=temporary-token'
scan_responses = []
scan._json = lambda status, body: scan_responses.append((status, body))
scan._authorized = lambda: False
scan.do_POST()
assert scan_responses == [(401, {'error': 'unauthorized'})], scan_responses
`;

test('User Scanner worker routes by pathname when Vercel appends query parameters', () => {
  const result = spawnSync('python3', ['-c', probe], {
    cwd: workerRoot,
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
});
