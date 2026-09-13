import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = path => readFileSync(path, 'utf8');

test('eval operator and orchestration docs define the offline trust boundary and schemas', () => {
  const operator = read('docs/PARA11AX-EVALS.md');
  const orchestration = read('docs/AGENT-ORCHESTRATION.md');

  for (const content of [operator, orchestration]) {
    assert.match(content, /para11ax-eval-result-v1\.0/i);
    assert.match(content, /para11ax-eval-scorecard-v1\.0/i);
    assert.match(content, /no model API calls|does not call model APIs|no model-provider API calls/i);
    assert.match(content, /no automatic routing mutation|does not automatically change|never automatically mutates/i);
  }
});

test('operator doc records exact manifest-driven promotion thresholds and CLI contract', () => {
  const operator = read('docs/PARA11AX-EVALS.md');
  assert.match(operator, /provenance[^\n]*2%/i);
  assert.match(operator, /handoff[^\n]*2%/i);
  assert.match(operator, /KQL[^\n]*3%/i);
  assert.match(operator, /weighted[^\n]*2%/i);
  assert.match(operator, /tolerance[^\n]*1%/i);
  assert.match(operator, /efficiency[^\n]*20%/i);
  assert.match(operator, /npm run eval:verify/i);
  assert.match(operator, /exit code 0/i);
  assert.match(operator, /exit code 2/i);
  assert.match(operator, /exit code 3/i);
});

test('orchestration doc makes internal eval evidence advisory and runtime-independent', () => {
  const orchestration = read('docs/AGENT-ORCHESTRATION.md');
  assert.match(orchestration, /public benchmarks[^\n]*(?:do not|never)[^\n]*change routes/i);
  assert.match(orchestration, /internal scorecard[^\n]*advisory/i);
  assert.match(orchestration, /production routing[^\n]*no runtime dependency[^\n]*eval/i);
});
