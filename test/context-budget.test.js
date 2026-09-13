import assert from 'node:assert/strict';
import test from 'node:test';
import { estimateTokens, planContextBudget, selectContextItems } from '../src/core/context-budget.js';

test('token estimator is deterministic and conservative for structured text', () => {
  assert.equal(estimateTokens(''), 0);
  assert.equal(estimateTokens('1234567'), 2);
  assert.equal(estimateTokens({ a: '1234567' }), estimateTokens(JSON.stringify({ a: '1234567' })));
});

test('context planner preserves explicit output, reasoning, and safety reserves', () => {
  const plan = planContextBudget({ contextWindow: 1_000_000, maxOutputTokens: 64_000 });
  assert.equal(plan.contextWindow, 1_000_000);
  assert.equal(plan.maxOutputTokens, 64_000);
  assert.ok(plan.reasoningReserveTokens >= 100_000);
  assert.ok(plan.safetyReserveTokens >= 50_000);
  assert.equal(plan.inputBudgetTokens + plan.maxOutputTokens + plan.reasoningReserveTokens + plan.safetyReserveTokens, 1_000_000);
  assert.ok(plan.allocations.evidence > plan.allocations.toolOutput);
  assert.ok(plan.allocations.activeWork > plan.allocations.scratch);
});

test('context selection keeps invariants and decisions before disposable tool noise', () => {
  const items = [
    { id: 'tool-old', kind: 'tool_output', text: 'x'.repeat(350), recency: 1 },
    { id: 'objective', kind: 'invariant', text: 'Objective: preserve exact scope.', recency: 1 },
    { id: 'decision', kind: 'decision', text: 'Decision: use canonical state.', recency: 2 },
    { id: 'tool-new', kind: 'tool_output', text: 'y'.repeat(350), recency: 10 },
    { id: 'ref', kind: 'artifact_ref', text: 'commit:abc', recency: 3 },
  ];

  const selected = selectContextItems(items, { maxTokens: 45 });
  assert.ok(selected.items.some(item => item.id === 'objective'));
  assert.ok(selected.items.some(item => item.id === 'decision'));
  assert.ok(selected.items.some(item => item.id === 'ref'));
  assert.ok(selected.dropped.some(item => item.kind === 'tool_output'));
  assert.ok(selected.usedTokens <= 45);
});

test('context selection fails closed when durable state alone exceeds the budget', () => {
  const items = [
    { id: 'objective', kind: 'invariant', text: 'x'.repeat(1000) },
    { id: 'decision', kind: 'decision', text: 'y'.repeat(1000) },
  ];
  assert.throws(() => selectContextItems(items, { maxTokens: 10 }), /durable context exceeds budget/i);
});
