const TASK_CLASSES = new Set(['simple_transform', 'research', 'coding', 'security_analysis', 'deep_reasoning', 'long_context', 'review', 'analysis']);
const LEVEL = Object.freeze({ economy: 0, balanced: 1, frontier: 2, frontier_max: 3 });
const EFFORT = Object.freeze(['low', 'medium', 'high', 'max']);
const WEIGHTS = Object.freeze({
  simple_transform: { coding: 0.05, reasoning: 0.10, knowledge: 0.10, longContext: 0.05, speed: 0.30, costEfficiency: 0.40 },
  research: { coding: 0.05, reasoning: 0.25, knowledge: 0.30, longContext: 0.20, speed: 0.05, costEfficiency: 0.15 },
  coding: { coding: 0.55, reasoning: 0.20, knowledge: 0.05, longContext: 0.05, speed: 0.10, costEfficiency: 0.05 },
  security_analysis: { coding: 0.15, reasoning: 0.35, knowledge: 0.25, longContext: 0.10, speed: 0.05, costEfficiency: 0.10 },
  deep_reasoning: { coding: 0.05, reasoning: 0.55, knowledge: 0.20, longContext: 0.10, speed: 0.025, costEfficiency: 0.075 },
  long_context: { coding: 0.05, reasoning: 0.20, knowledge: 0.15, longContext: 0.45, speed: 0.05, costEfficiency: 0.10 },
  review: { coding: 0.15, reasoning: 0.40, knowledge: 0.20, longContext: 0.10, speed: 0.05, costEfficiency: 0.10 },
  analysis: { coding: 0.10, reasoning: 0.35, knowledge: 0.25, longContext: 0.10, speed: 0.05, costEfficiency: 0.15 },
});

function enumValue(value, allowed, field) {
  if (!allowed.has(value)) throw new TypeError(`invalid model route: ${field}`);
  return value;
}

function atLeast(current, minimum) {
  return LEVEL[current] >= LEVEL[minimum] ? current : minimum;
}

export function routeModelTask({
  taskClass = 'analysis',
  complexity = 'medium',
  risk = 'medium',
  contextTokens = 0,
  latencySensitive = false,
  costSensitive = false,
  failures = 0,
} = {}) {
  enumValue(taskClass, TASK_CLASSES, 'taskClass');
  enumValue(complexity, new Set(['low', 'medium', 'high']), 'complexity');
  enumValue(risk, new Set(['low', 'medium', 'high']), 'risk');
  if (!Number.isSafeInteger(failures) || failures < 0) throw new TypeError('invalid model route: failures');
  if (!Number.isFinite(contextTokens) || contextTokens < 0) throw new TypeError('invalid model route: contextTokens');

  let tier = 'balanced';
  let reasoningEffort = 'medium';
  let requireIndependentReview = false;
  let requireDifferentFamilyReviewer = false;
  const reasons = [];

  switch (taskClass) {
    case 'simple_transform':
      tier = 'economy'; reasoningEffort = 'low'; reasons.push('routine_transform'); break;
    case 'coding':
      tier = 'frontier'; reasoningEffort = 'high'; reasons.push('coding_agent_quality'); break;
    case 'security_analysis':
      tier = 'frontier'; reasoningEffort = 'high'; reasons.push('security_reasoning'); break;
    case 'deep_reasoning':
      tier = 'frontier_max'; reasoningEffort = 'max'; requireIndependentReview = true; reasons.push('deep_reasoning'); break;
    case 'long_context':
      tier = 'frontier'; reasoningEffort = 'high'; reasons.push('long_context_reliability'); break;
    case 'review':
      tier = 'frontier'; reasoningEffort = 'high'; requireIndependentReview = true; requireDifferentFamilyReviewer = true; reasons.push('independent_review'); break;
    case 'research':
    case 'analysis':
    default:
      if (complexity === 'high') { tier = 'frontier'; reasoningEffort = 'high'; reasons.push('high_complexity'); }
      else reasons.push('balanced_default');
  }

  if (complexity === 'high' && taskClass !== 'deep_reasoning') {
    tier = atLeast(tier, 'frontier');
    reasoningEffort = EFFORT[Math.max(EFFORT.indexOf(reasoningEffort), EFFORT.indexOf('high'))];
  }

  if (costSensitive && risk !== 'high' && complexity === 'low' && LEVEL[tier] <= LEVEL.balanced) {
    tier = 'economy';
    reasoningEffort = 'low';
    reasons.push('cost_sensitive');
  }

  if (latencySensitive && risk === 'low' && complexity !== 'high' && reasoningEffort === 'medium') {
    reasoningEffort = 'low';
    reasons.push('latency_sensitive');
  }

  if (contextTokens >= 250_000) reasons.push('large_context');

  if (risk === 'high') {
    tier = atLeast(tier, 'frontier');
    reasoningEffort = EFFORT[Math.max(EFFORT.indexOf(reasoningEffort), EFFORT.indexOf('high'))];
    requireIndependentReview = true;
    requireDifferentFamilyReviewer = true;
    reasons.push('high_risk_review_gate');
  }

  if (failures >= 2) {
    tier = 'frontier_max';
    reasoningEffort = 'max';
    requireIndependentReview = true;
    requireDifferentFamilyReviewer = true;
    reasons.push('failure_escalation');
  } else if (failures === 1) {
    tier = atLeast(tier, 'frontier');
    reasoningEffort = EFFORT[Math.max(EFFORT.indexOf(reasoningEffort), EFFORT.indexOf('high'))];
    reasons.push('single_failure_escalation');
  }

  return Object.freeze({
    taskClass,
    tier,
    reasoningEffort,
    requireIndependentReview,
    requireDifferentFamilyReviewer,
    contextPolicy: contextTokens >= 250_000 ? 'durable-state-plus-jit-retrieval' : 'durable-state-first',
    benchmarkSnapshot: '2026-09-13',
    reasons: Object.freeze([...new Set(reasons)]),
  });
}

function score(value, field) {
  if (!Number.isFinite(value) || value < 0 || value > 100) throw new TypeError(`invalid model candidate: ${field}`);
  return Number(value);
}

function normalizeModel(model) {
  if (!model || typeof model !== 'object' || Array.isArray(model)) throw new TypeError('invalid model candidate');
  const id = String(model.id ?? '').trim();
  const family = String(model.family ?? '').trim();
  if (!id || !family || !Number.isSafeInteger(model.contextWindow) || model.contextWindow <= 0) throw new TypeError('invalid model candidate');
  return {
    ...model,
    id,
    family,
    coding: score(model.coding, 'coding'),
    reasoning: score(model.reasoning, 'reasoning'),
    knowledge: score(model.knowledge, 'knowledge'),
    longContext: score(model.longContext, 'longContext'),
    speed: score(model.speed, 'speed'),
    costEfficiency: score(model.costEfficiency, 'costEfficiency'),
  };
}

export function rankModelCandidates(models, { taskClass = 'analysis', contextTokens = 0, excludeFamilies = [] } = {}) {
  enumValue(taskClass, TASK_CLASSES, 'taskClass');
  if (!Array.isArray(models) || !Array.isArray(excludeFamilies)) throw new TypeError('invalid model candidates');
  if (!Number.isFinite(contextTokens) || contextTokens < 0) throw new TypeError('invalid model route: contextTokens');
  const excluded = new Set(excludeFamilies);
  const weights = WEIGHTS[taskClass];
  return models
    .map(normalizeModel)
    .filter(model => model.contextWindow >= contextTokens && !excluded.has(model.family))
    .map(model => ({
      ...model,
      routeScore: Object.entries(weights).reduce((total, [metric, weight]) => total + (model[metric] * weight), 0),
    }))
    .sort((left, right) => right.routeScore - left.routeScore || right.costEfficiency - left.costEfficiency || left.id.localeCompare(right.id));
}
