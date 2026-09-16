function finiteNonNegative(value, field) {
  const number = Number(value);
  if (!Number.isFinite(number) || number < 0) throw new TypeError(`${field} must be a finite non-negative number`);
  return number;
}

function normalizeRate(value, field) {
  const number = finiteNonNegative(value, field);
  if (number > 1) throw new TypeError(`${field} must be between 0 and 1`);
  return number;
}

function percentile(values, quantile) {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const rank = Math.max(1, Math.ceil(quantile * sorted.length));
  return sorted[Math.min(sorted.length - 1, rank - 1)];
}

function freezeDecision(admitted, reasons) {
  return Object.freeze({ admitted, reasons: Object.freeze(reasons) });
}

export function summarizeProviderBenchmark(observations) {
  if (!Array.isArray(observations) || observations.length === 0) {
    throw new TypeError('observations must be a non-empty array');
  }

  let uniqueFacts = 0;
  let uniqueGraphEdges = 0;
  let errors = 0;
  let noResults = 0;
  let decisionChangingObservations = 0;
  let materialUniqueObservations = 0;
  const latencies = [];

  for (const observation of observations) {
    if (!observation || typeof observation !== 'object' || Array.isArray(observation)) {
      throw new TypeError('benchmark observation must be an object');
    }

    latencies.push(finiteNonNegative(observation.latencyMs ?? 0, 'latencyMs'));
    uniqueFacts += finiteNonNegative(observation.uniqueFacts ?? 0, 'uniqueFacts');
    uniqueGraphEdges += finiteNonNegative(observation.uniqueGraphEdges ?? 0, 'uniqueGraphEdges');
    materialUniqueObservations += finiteNonNegative(observation.materialUniqueObservations ?? 0, 'materialUniqueObservations');

    const status = String(observation.status ?? '').trim().toLowerCase();
    if (status === 'no_result') noResults += 1;
    else if (['error', 'failure', 'timeout', 'rate_limited'].includes(status)) errors += 1;
    else if (status !== 'observed') throw new TypeError(`unsupported benchmark status: ${status || '<empty>'}`);

    if (observation.decisionChanging === true) decisionChangingObservations += 1;
  }

  const calls = observations.length;
  return Object.freeze({
    uniqueFacts,
    uniqueGraphEdges,
    latencyP50Ms: percentile(latencies, 0.5),
    latencyP95Ms: percentile(latencies, 0.95),
    errorRate: errors / calls,
    noResultRate: noResults / calls,
    decisionChangingObservations,
    materialUniqueObservationsPerCall: materialUniqueObservations / calls,
  });
}

function evaluateBaseline(metrics, thresholds) {
  const reasons = [];
  if (metrics.uniqueFacts < finiteNonNegative(thresholds.minUniqueFacts ?? 0, 'baseline.minUniqueFacts')) reasons.push('insufficient_unique_facts');
  if (metrics.materialUniqueObservationsPerCall < finiteNonNegative(thresholds.minMaterialUniqueObservationsPerCall ?? 0, 'baseline.minMaterialUniqueObservationsPerCall')) reasons.push('insufficient_material_unique_observations');
  if (metrics.latencyP95Ms > finiteNonNegative(thresholds.maxLatencyP95Ms ?? Number.MAX_SAFE_INTEGER, 'baseline.maxLatencyP95Ms')) reasons.push('latency_p95_exceeds_limit');
  if (metrics.errorRate > normalizeRate(thresholds.maxErrorRate ?? 1, 'baseline.maxErrorRate')) reasons.push('error_rate_exceeds_limit');
  return freezeDecision(reasons.length === 0, reasons);
}

function evaluateGraph(metrics, thresholds) {
  const reasons = [];
  if (metrics.uniqueGraphEdges < finiteNonNegative(thresholds.minUniqueGraphEdges ?? 0, 'graph.minUniqueGraphEdges')) reasons.push('insufficient_unique_graph_edges');
  if (metrics.materialUniqueObservationsPerCall < finiteNonNegative(thresholds.minMaterialUniqueObservationsPerCall ?? 0, 'graph.minMaterialUniqueObservationsPerCall')) reasons.push('insufficient_material_unique_observations');
  if (metrics.latencyP95Ms > finiteNonNegative(thresholds.maxLatencyP95Ms ?? Number.MAX_SAFE_INTEGER, 'graph.maxLatencyP95Ms')) reasons.push('latency_p95_exceeds_limit');
  if (metrics.errorRate > normalizeRate(thresholds.maxErrorRate ?? 1, 'graph.maxErrorRate')) reasons.push('error_rate_exceeds_limit');
  return freezeDecision(reasons.length === 0, reasons);
}

export function admitToAutomaticWorkflow(metrics, thresholds) {
  if (!metrics || typeof metrics !== 'object' || Array.isArray(metrics)) throw new TypeError('metrics must be an object');
  if (!thresholds || typeof thresholds !== 'object' || Array.isArray(thresholds)) throw new TypeError('thresholds must be an object');

  const normalizedMetrics = Object.freeze({
    uniqueFacts: finiteNonNegative(metrics.uniqueFacts, 'metrics.uniqueFacts'),
    uniqueGraphEdges: finiteNonNegative(metrics.uniqueGraphEdges, 'metrics.uniqueGraphEdges'),
    latencyP50Ms: finiteNonNegative(metrics.latencyP50Ms, 'metrics.latencyP50Ms'),
    latencyP95Ms: finiteNonNegative(metrics.latencyP95Ms, 'metrics.latencyP95Ms'),
    errorRate: normalizeRate(metrics.errorRate, 'metrics.errorRate'),
    noResultRate: normalizeRate(metrics.noResultRate, 'metrics.noResultRate'),
    decisionChangingObservations: finiteNonNegative(metrics.decisionChangingObservations, 'metrics.decisionChangingObservations'),
    materialUniqueObservationsPerCall: finiteNonNegative(metrics.materialUniqueObservationsPerCall, 'metrics.materialUniqueObservationsPerCall'),
  });

  return Object.freeze({
    baseline: evaluateBaseline(normalizedMetrics, thresholds.baseline ?? {}),
    graph: evaluateGraph(normalizedMetrics, thresholds.graph ?? {}),
  });
}
