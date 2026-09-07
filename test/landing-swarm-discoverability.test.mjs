import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const landing = readFileSync(new URL('../index.html', import.meta.url), 'utf8');

test('landing page advertises all three analyst utilities including GreyNoise Swarm', () => {
  assert.match(landing, /<small>analyst utilities<\/small><strong>3<\/strong>/i);
  assert.match(landing, /USER SCANNER\s*·\s*SHODAN\s*·\s*GREYNOISE SWARM/i);
  assert.match(landing, /<b>GREYNOISE SWARM<\/b>/i);
  assert.match(landing, /GreyNoise Swarm/i);
});
