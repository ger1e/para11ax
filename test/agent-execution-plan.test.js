import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { buildAgentExecutionPlan } from '../src/core/agent-execution-plan.js';
import {
  createMissionWorkspace,
  reduceMissionWorkspace,
} from '../src/core/mission/workspace.js';

const profileInput = {
  id: 'ultraviolet',
  name: 'CLIENT-ULTRAVIOLET-SECRET',
  technologies: ['fortinet'],
  telemetry: ['DeviceNetworkEvents'],
};

test('mission execution plan automatically routes security analysis and budgets context', () => {
  const workspace = createMissionWorkspace();
  const plan = buildAgentExecutionPlan(workspace, {
    contextWindow: 128_000,
    maxOutputTokens: 16_384,
  });

  assert.equal(plan.schemaVersion, 'para11ax-agent-execution-plan-v1.0');
  assert.equal(plan.route.taskClass, 'security_analysis');
  assert.equal(plan.route.tier, 'frontier');
  assert.equal(plan.route.reasoningEffort, 'high');
  assert.equal(plan.route.contextPolicy, 'durable-state-first');
  assert.equal(plan.budget.contextWindow, 128_000);
  assert.equal(plan.budget.maxOutputTokens, 16_384);
  assert.ok(plan.budget.inputBudgetTokens > 0);
  assert.ok(plan.budget.selectedTokens <= plan.budget.inputBudgetTokens);
  assert.ok(plan.context.selectedIds.includes('mission-handoff'));
  assert.equal(Object.isFrozen(plan), true);
  assert.equal(Object.isFrozen(plan.route), true);
  assert.equal(Object.isFrozen(plan.context.selectedIds), true);
});

test('repeated host failures deterministically escalate the route', () => {
  const plan = buildAgentExecutionPlan(createMissionWorkspace(), { failures: 2 });
  assert.equal(plan.route.tier, 'frontier_max');
  assert.equal(plan.route.reasoningEffort, 'max');
  assert.equal(plan.route.requireIndependentReview, true);
  assert.equal(plan.route.requireDifferentFamilyReviewer, true);
  assert.ok(plan.route.reasons.includes('failure_escalation'));
});

test('large-context routing uses JIT retrieval policy without exceeding the input budget', () => {
  const plan = buildAgentExecutionPlan(createMissionWorkspace(), {
    contextWindow: 400_000,
    maxOutputTokens: 32_000,
  });
  assert.equal(plan.route.contextPolicy, 'durable-state-first');
  assert.ok(plan.budget.selectedTokens <= plan.budget.inputBudgetTokens);
  assert.equal(plan.budget.reasoningBudgetPolicy, 'inside-max-output');
});

test('routing telemetry is aggregate-only and never contains mission payload values', () => {
  const workspace = reduceMissionWorkspace(createMissionWorkspace(), {
    type: 'PROFILE_SET',
    value: profileInput,
  });
  const plan = buildAgentExecutionPlan(workspace);
  const serialized = JSON.stringify(plan.telemetry);

  assert.equal(plan.telemetry.schemaVersion, 'para11ax-agent-routing-telemetry-v1.0');
  assert.equal(plan.telemetry.taskClass, 'security_analysis');
  assert.equal(plan.telemetry.tier, 'frontier');
  assert.equal(plan.telemetry.selectedContextItems, plan.context.selectedIds.length);
  assert.equal(plan.telemetry.droppedContextItems, plan.context.droppedIds.length);
  assert.equal(serialized.includes('CLIENT-ULTRAVIOLET-SECRET'), false);
  assert.equal(serialized.includes('fortinet'), false);
  assert.equal(serialized.includes('DeviceNetworkEvents'), false);
  assert.equal(Object.isFrozen(plan.telemetry), true);
});

test('execution plan context projection exposes identifiers only, never selected values', () => {
  const workspace = reduceMissionWorkspace(createMissionWorkspace(), {
    type: 'PROFILE_SET',
    value: profileInput,
  });
  const plan = buildAgentExecutionPlan(workspace);
  const serialized = JSON.stringify(plan.context);

  assert.deepEqual(Object.keys(plan.context).sort(), ['droppedIds', 'selectedIds']);
  assert.equal(serialized.includes('CLIENT-ULTRAVIOLET-SECRET'), false);
  assert.equal(serialized.includes('fortinet'), false);
});

test('Mission MCP host path attaches the execution plan instead of leaving policy dead', () => {
  const source = readFileSync(new URL('../src/mcp/server.js', import.meta.url), 'utf8');
  assert.match(source, /import\s*\{\s*buildAgentExecutionPlan\s*\}\s*from\s*['"]\.\.\/core\/agent-execution-plan\.js['"]/);
  assert.match(source, /executionPlan\s*:\s*buildAgentExecutionPlan\(/);
});
