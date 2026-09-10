import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const script = await readFile(new URL('../scripts/configure-vercel-firewall.ps1', import.meta.url), 'utf8').catch(() => '');
const smoke = await readFile(new URL('../.github/workflows/tooling-smoke.yml', import.meta.url), 'utf8');

test('Vercel firewall configuration is pinned to the canonical PARA11AX project', () => {
  assert.match(script, /\$ProjectName\s*=\s*'para11ax'/);
  assert.match(script, /\$ProjectId\s*=\s*'prj_ojUpOTw8x8KOj9CrTs8jih1mrPjo'/);
  assert.match(script, /\$TeamSlug\s*=\s*'geri6'/);
  assert.match(script, /\$PinnedVercelCliVersion\s*=\s*'58\.4\.4'/);
  assert.match(script, /vercel\.cmd/);
  assert.match(script, /whoami/);
});

test('Vercel firewall rule rate-limits only POST PARA11AX API traffic by source IP', () => {
  assert.match(script, /\$RuleName\s*=\s*'para11ax-api-post-rate-limit'/);
  assert.match(script, /\{"type":"path","op":"pre","value":"\/api\/para11ax\/"\}/);
  assert.match(script, /\{"type":"method","op":"eq","value":"POST"\}/);
  assert.match(script, /--action\s+rate_limit/);
  assert.match(script, /--rate-limit-window\s+60/);
  assert.match(script, /--rate-limit-requests\s+30/);
  assert.match(script, /--rate-limit-keys\s+ip/);
  assert.match(script, /--rate-limit-algo\s+fixed_window/);
  assert.match(script, /--rate-limit-action\s+rate_limit/);
});

test('Vercel firewall configuration is idempotent and stages before human-reviewed publication', () => {
  assert.match(script, /firewall\s+rules\s+inspect\s+\$RuleName/);
  assert.match(script, /firewall\s+rules\s+edit\s+\$RuleName/);
  assert.match(script, /firewall\s+rules\s+add\s+\$RuleName/);
  assert.match(script, /firewall\s+diff/);
  assert.doesNotMatch(script, /Invoke-NativeChecked[^\n]*firewall\s+publish/);
  assert.match(script, /vercel firewall publish --yes/);
});

test('Vercel firewall helper adds no token transport and is syntax-gated in hosted CI', () => {
  assert.doesNotMatch(script, /VERCEL_TOKEN|Authorization:|api\.vercel\.com|Invoke-WebRequest|Invoke-RestMethod/);
  assert.match(smoke, /scripts\/configure-vercel-firewall\.ps1/);
});
