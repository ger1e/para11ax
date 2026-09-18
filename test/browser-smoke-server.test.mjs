import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import test from 'node:test';

const repoRoot = new URL('..', import.meta.url);

async function startSmokeServer() {
  const child = spawn(process.execPath, ['scripts/serve-browser-smoke.mjs'], {
    cwd: repoRoot,
    env: { ...process.env, BROWSER_SMOKE_PORT: '0' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk; });

  const url = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`browser smoke server did not start: ${stderr}`)), 5_000);
    child.stdout.on('data', chunk => {
      const match = String(chunk).match(/listening on (http:\/\/127\.0\.0\.1:\d+)/);
      if (!match) return;
      clearTimeout(timeout);
      resolve(match[1]);
    });
    child.once('exit', code => {
      clearTimeout(timeout);
      reject(new Error(`browser smoke server exited ${code}: ${stderr}`));
    });
  });
  return { child, url };
}

async function stopSmokeServer(child) {
  if (child.exitCode !== null) return;
  await new Promise(resolve => {
    child.once('exit', resolve);
    child.kill('SIGTERM');
  });
}

test('browser smoke server reproduces production app rewrites and not-found status', { timeout: 10_000 }, async t => {
  const server = await startSmokeServer();
  t.after(() => stopSmokeServer(server.child));

  const app = await fetch(`${server.url}/app/`);
  assert.equal(app.status, 200);
  assert.match(await app.text(), /<script type="module" src="\/app\/app\.js"><\/script>/);

  const entry = await fetch(`${server.url}/app/app.js`);
  assert.equal(entry.status, 200);
  assert.match(await entry.text(), /await import\('\.\/terminal-entry\.js'\)/);

  const styles = await fetch(`${server.url}/app/app.css`);
  assert.equal(styles.status, 200);
  assert.match(await styles.text(), /@import url\('\/app\/app-base\.css'\)/);

  const module = await fetch(`${server.url}/app/terminal-entry.js`);
  assert.equal(module.status, 200);
  assert.match(await module.text(), /createPara11axBootSequence/);

  const missing = await fetch(`${server.url}/does-not-exist.js`);
  assert.equal(missing.status, 404);
  assert.match(missing.headers.get('content-type') || '', /text\/html/);
});
