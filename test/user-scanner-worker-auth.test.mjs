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
stub_worker.run_scan = lambda payload: {'summary': {'total_scanned': 0, 'found': 0, 'not_found': 0, 'errors': 0, 'skipped': 0}, 'results': [], 'errored_sites': []}
sys.modules['worker'] = stub_worker

spec = importlib.util.spec_from_file_location('user_scanner_api', root / 'api' / 'index.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class Headers:
    def __init__(self, authorization=''):
        self.authorization = authorization
    def get(self, name, default=''):
        return self.authorization if name.lower() == 'authorization' else default

module._verify_vercel_oidc = lambda token: token == 'valid-vercel-oidc'

for supplied, expected in [
    ('', False),
    ('Bearer invalid', False),
    ('Bearer valid-vercel-oidc', True),
]:
    req = module.handler.__new__(module.handler)
    req.headers = Headers(supplied)
    assert req._authorized() is expected, (supplied, req._authorized())
`;

test('User Scanner worker fails closed and accepts only verified Vercel workload identity without static secret', () => {
  const result = spawnSync('python3', ['-c', probe], {
    cwd: workerRoot,
    encoding: 'utf8',
    env: { ...process.env, USER_SCANNER_WORKER_TOKEN: '' },
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
});
