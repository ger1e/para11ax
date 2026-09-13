export const AGENT_TASK_CLASSES = Object.freeze([
  'simple_transform',
  'research',
  'coding',
  'security_analysis',
  'cyber_research',
  'deep_reasoning',
  'long_context',
  'review',
  'analysis',
]);

export const AGENT_RISK_LEVELS = Object.freeze(['low', 'medium', 'high']);

const TASK_CLASS_SET = new Set(AGENT_TASK_CLASSES);
const RISK_LEVEL_SET = new Set(AGENT_RISK_LEVELS);

export function isAgentTaskClass(value) {
  return TASK_CLASS_SET.has(value);
}

export function isAgentRiskLevel(value) {
  return RISK_LEVEL_SET.has(value);
}
