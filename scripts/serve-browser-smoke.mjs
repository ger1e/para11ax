import { createReadStream } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import { createServer } from 'node:http';
import { extname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
const vercel = JSON.parse(await readFile(resolve(repoRoot, 'vercel.json'), 'utf8'));
const host = process.env.BROWSER_SMOKE_HOST || '127.0.0.1';
const port = Number.parseInt(process.env.BROWSER_SMOKE_PORT || '4173', 10);

if (!Number.isInteger(port) || port < 0 || port > 65_535) throw new Error('invalid browser smoke port');

const contentTypes = new Map([
  ['.css', 'text/css; charset=utf-8'],
  ['.html', 'text/html; charset=utf-8'],
  ['.ico', 'image/x-icon'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
  ['.mjs', 'text/javascript; charset=utf-8'],
  ['.png', 'image/png'],
  ['.svg', 'image/svg+xml'],
  ['.txt', 'text/plain; charset=utf-8'],
  ['.woff2', 'font/woff2'],
]);

async function existingFile(pathname) {
  let decoded;
  try { decoded = decodeURIComponent(pathname); } catch { return null; }
  const candidate = resolve(repoRoot, `.${decoded}`);
  if (candidate !== repoRoot && !candidate.startsWith(`${repoRoot}${sep}`)) return null;
  try {
    const metadata = await stat(candidate);
    return metadata.isFile() ? candidate : null;
  } catch {
    return null;
  }
}

async function resolveStaticRequest(pathname) {
  for (const route of vercel.routes || []) {
    if (route.handle === 'filesystem') {
      const direct = await existingFile(pathname);
      if (direct) return { file: direct, status: 200 };
      continue;
    }
    if (!route.src || !route.dest) continue;
    const matcher = new RegExp(`^${route.src}$`);
    if (!matcher.test(pathname)) continue;
    const destination = pathname.replace(matcher, route.dest).split('?', 1)[0];
    const rewritten = await existingFile(destination);
    if (rewritten) return { file: rewritten, status: route.status || 200 };
  }
  const direct = await existingFile(pathname);
  return direct ? { file: direct, status: 200 } : null;
}

const server = createServer(async (request, response) => {
  if (!['GET', 'HEAD'].includes(request.method || '')) {
    response.writeHead(405, { Allow: 'GET, HEAD' });
    response.end();
    return;
  }

  const pathname = new URL(request.url || '/', `http://${host}:${port}`).pathname;
  const resolved = await resolveStaticRequest(pathname);
  if (!resolved) {
    response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    response.end('Not found');
    return;
  }

  response.writeHead(resolved.status, {
    'Cache-Control': 'no-store',
    'Content-Type': contentTypes.get(extname(resolved.file).toLowerCase()) || 'application/octet-stream',
    'X-Content-Type-Options': 'nosniff',
  });
  if (request.method === 'HEAD') response.end();
  else createReadStream(resolved.file).pipe(response);
});

server.listen(port, host, () => {
  const address = server.address();
  const activePort = typeof address === 'object' && address ? address.port : port;
  process.stdout.write(`PARA11AX browser smoke server listening on http://${host}:${activePort}\n`);
});

const close = () => server.close(() => process.exit(0));
process.once('SIGINT', close);
process.once('SIGTERM', close);
