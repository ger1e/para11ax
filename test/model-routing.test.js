import assert from 'node:assert/strict';
import test from 'node:test';
import { rankModelCandidates, routeModelTask } from '../src/core/model-routing.js';

test('routes routine transforms to economy tier with low reasoning', () => {
  const route = routeModelTask({ taskClass: 'simple_transform', complexity: 'low', risk: 'low', costSensitive: true });
  assert.equal(route.tier, 'economy');
  assert.equal(route.reasoningEffort, 'low');
  assert.equal(route.requireIndependentReview, false);
});

test('routes coding and high-risk security work to frontier reasoning with review gates', () => {
  const coding = routeModelTask({ taskClass: 'coding', complexity: 'high', risk: 'medium' });
  assert.equal(coding.tier, 'frontier');
  assert.equal(coding.reasoningEffort, 'high');

  const security = routeModelTask({ taskClass: 'security_analysis', complexity: 'high', risk: 'high' });
  assert.equal(security.tier, 'frontier');
  assert.equal(security.reasoningEffort, 'high');
  assert.equal(security.requireIndependentReview, true);
  assert.equal(security.requireDifferentFamilyReviewer, true);
});

test('escalates repeated failures instead of burning tokens at the same capability level', () => {
  const route = routeModelTask({ taskClass: 'coding', failures: 2, risk: 'medium' });
  assert.equal(route.tier, 'frontier_max');
  assert.equal(route.reasoningEffort, 'max');
  assert.equal(route.requireIndependentReview, true);
});

test('high risk cannot be cost-demoted below frontier', () => {
  const route = routeModelTask({ taskClass: 'research', risk: 'high', costSensitive: true, complexity: 'low' });
  assert.notEqual(route.tier, 'economy');
  assert.equal(route.requireIndependentReview, true);
});

test('candidate ranking is task-specific, context-aware, and can enforce model-family diversity', () => {
  const models = [
    { id: 'cheap', family: 'a', contextWindow: 1_000_000, coding: 60, reasoning: 60, knowledge: 60, longContext: 70, speed: 95, costEfficiency: 100 },
    { id: 'coder', family: 'b', contextWindow: 1_000_000, coding: 95, reasoning: 80, knowledge: 75, longContext: 80, speed: 60, costEfficiency: 65 },
    { id: 'reasoner', family: 'c', contextWindow: 1_000_000, coding: 75, reasoning: 98, knowledge: 90, longContext: 90, speed: 45, costEfficiency: 45 },
    { id: 'small-context', family: 'd', contextWindow: 32_000, coding: 100, reasoning: 100, knowledge: 100, longContext: 100, speed: 100, costEfficiency: 100 },
  ];

  const coding = rankModelCandidates(models, { taskClass: 'coding', contextTokens: 100_000 });
  assert.equal(coding[0].id, 'coder');
  assert.equal(coding.some(item => item.id === 'small-context'), false);

  const reasoning = rankModelCandidates(models, { taskClass: 'deep_reasoning', contextTokens: 100_000, excludeFamilies: ['b'] });
  assert.equal(reasoning[0].id, 'reasoner');
  assert.equal(reasoning.some(item => item.family === 'b'), false);
});
