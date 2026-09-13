import {
  estimateTokens,
  planContextBudget,
  selectContextItems,
} from './context-budget.js';
import { routeModelTask } from './model-routing.js';
import { importMissionWorkspace } from './mission/workspace.js';

export const AGENT_EXECUTION_PLAN_SCHEMA = 'para11ax-agent-execution-plan-v1.0';
export const AGENT_ROUTING_TELEMETRY_SCHEMA = 'para11ax-agent-routing-telemetry-v1.0';

const DEFAULT_CONTEXT_WINDOW = 128_000;
const DEFAULT_MAX_OUTPUT_TOKENS = 16_384;

function contextItem(id, kind, value) {
  if (value === null || value === undefined) return null;
  return Object.freeze({ id, kind, text: value, tokens: Math.max(1, estimateTokens(value)) });
}

function candidateContext(workspace) {
  return [
    contextItem('mission-handoff', 'invariant', workspace.handoff),
    contextItem('mission-agent-state', 'decision', workspace.agentState),
    contextItem('mission-profile', 'recent', workspace.profile),
    contextItem('mission-context', 'evidence', workspace.context),
    contextItem('mission-relevance', 'evidence', workspace.relevance),
    contextItem('mission-hunt', 'evidence', workspace.hunt),
    workspace.kqlValidations.length
      ? contextItem('mission-kql-validations', 'artifact_ref', workspace.kqlValidations)
      : null,
    contextItem('mission-result', 'evidence', workspace.result),
    contextItem('mission-servicenow', 'tool_output', workspace.serviceNow),
  ].filter(Boolean);
}

export function buildAgentExecutionPlan(workspace, {
  contextWindow = DEFAULT_CONTEXT_WINDOW,
  maxOutputTokens = DEFAULT_MAX_OUTPUT_TOKENS,
  safetyReserveRatio = 0.05,
  complexity = 'medium',
  failures = 0,
  latencySensitive = false,
  costSensitive = false,
} = {}) {
  const current = importMissionWorkspace(workspace);
  const candidates = candidateContext(current);
  const candidateTokens = candidates.reduce((sum, item) => sum + item.tokens, 0);
  const route = routeModelTask({
    taskClass: current.agentState.taskClass,
    risk: current.agentState.risk,
    complexity,
    contextTokens: candidateTokens,
    latencySensitive,
    costSensitive,
    failures,
  });
  const plannedBudget = planContextBudget({
    contextWindow,
    maxOutputTokens,
    safetyReserveRatio,
  });
  const selection = selectContextItems(candidates, {
    maxTokens: plannedBudget.inputBudgetTokens,
  });

  const selectedIds = Object.freeze(selection.items.map(item => item.id));
  const droppedIds = Object.freeze(selection.dropped.map(item => item.id));
  const droppedTokens = candidateTokens - selection.usedTokens;

  const budget = Object.freeze({
    contextWindow: plannedBudget.contextWindow,
    maxOutputTokens: plannedBudget.maxOutputTokens,
    reasoningBudgetPolicy: plannedBudget.reasoningBudgetPolicy,
    safetyReserveTokens: plannedBudget.safetyReserveTokens,
    inputBudgetTokens: plannedBudget.inputBudgetTokens,
    candidateTokens,
    selectedTokens: selection.usedTokens,
    droppedTokens,
    pressure: selection.pressure,
    strategy: selection.strategy,
  });

  const context = Object.freeze({ selectedIds, droppedIds });
  const telemetry = Object.freeze({
    schemaVersion: AGENT_ROUTING_TELEMETRY_SCHEMA,
    taskClass: route.taskClass,
    risk: current.agentState.risk,
    tier: route.tier,
    reasoningEffort: route.reasoningEffort,
    specialistHint: route.specialistHint,
    contextPolicy: route.contextPolicy,
    requireIndependentReview: route.requireIndependentReview,
    requireDifferentFamilyReviewer: route.requireDifferentFamilyReviewer,
    candidateTokens,
    selectedContextTokens: selection.usedTokens,
    selectedContextItems: selectedIds.length,
    droppedContextItems: droppedIds.length,
    contextPressure: selection.pressure,
    failures,
    benchmarkSnapshot: route.benchmarkSnapshot,
  });

  return Object.freeze({
    schemaVersion: AGENT_EXECUTION_PLAN_SCHEMA,
    route,
    budget,
    context,
    telemetry,
  });
}
